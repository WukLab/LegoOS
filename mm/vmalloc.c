/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Managing the kernel virtual address used by ioremap()
 * For details of kernel va layout, refer to Documentation/mm.txt
 */

#include <lego/mm.h>
#include <lego/err.h>
#include <lego/numa.h>
#include <lego/list.h>
#include <lego/slab.h>
#include <lego/rbtree.h>
#include <lego/kernel.h>
#include <lego/vmalloc.h>
#include <lego/spinlock.h>

#define VM_VM_AREA	0x04
static DEFINE_SPINLOCK(vmap_area_lock);
static LIST_HEAD(vmap_area_list);
static struct rb_root vmap_area_root = RB_ROOT;

/* The vmap cache globals are protected by vmap_area_lock */
static struct rb_node *free_vmap_cache;
static unsigned long cached_hole_size;
static unsigned long cached_vstart;
static unsigned long cached_align;

static unsigned long vmap_area_pcpu_hole = VMALLOC_END;

/* TODO: Use kmalloc and kfree once slab is built */
static struct vmap_area *get_next_vmap_area(void)
{
	return (struct vmap_area *)((void *)get_zeroed_page(GFP_KERNEL));
}

static void free_vmap_area(struct vmap_area *va)
{
	free_page((unsigned long)va);

	/*
	 * Track the highest possible candidate for pcpu area
	 * allocation.  Areas outside of vmalloc area can be returned
	 * here too, consider only end addresses which fall inside
	 * vmalloc area proper.
	 */
	if (va->va_end > VMALLOC_START && va->va_end <= VMALLOC_END)
		vmap_area_pcpu_hole = max(vmap_area_pcpu_hole, va->va_end);
}

static struct vm_struct *get_next_vm_struct(void)
{
	return (struct vm_struct *)((void *)get_zeroed_page(GFP_KERNEL));
}

static void free_vm_struct(struct vm_struct *vs)
{
	free_page((unsigned long)vs);
}

static struct vmap_area *__find_vmap_area(unsigned long addr)
{
	struct rb_node *n = vmap_area_root.rb_node;

	while (n) {
		struct vmap_area *va;

		va = rb_entry(n, struct vmap_area, rb_node);
		if (addr < va->va_start)
			n = n->rb_left;
		else if (addr >= va->va_end)
			n = n->rb_right;
		else
			return va;
	}

	return NULL;
}

static void __insert_vmap_area(struct vmap_area *va)
{
	struct rb_node **p = &vmap_area_root.rb_node;
	struct rb_node *parent = NULL;
	struct rb_node *tmp;

	while (*p) {
		struct vmap_area *tmp_va;

		parent = *p;
		tmp_va = rb_entry(parent, struct vmap_area, rb_node);
		if (va->va_start < tmp_va->va_end)
			p = &(*p)->rb_left;
		else if (va->va_end > tmp_va->va_start)
			p = &(*p)->rb_right;
		else
			BUG();
	}

	rb_link_node(&va->rb_node, parent, p);
	rb_insert_color(&va->rb_node, &vmap_area_root);

	/* address-sort this list */
	tmp = rb_prev(&va->rb_node);
	if (tmp) {
		struct vmap_area *prev;
		prev = rb_entry(tmp, struct vmap_area, rb_node);
		list_add(&va->list, &prev->list);
	} else
		list_add(&va->list, &vmap_area_list);
}

/*
 * Allocate a region of KVA of the specified size and alignment,
 * within the vstart and vend.
 */
static struct vmap_area *alloc_vmap_area(unsigned long size,
				unsigned long align,
				unsigned long vstart, unsigned long vend,
				int node, gfp_t gfp_mask)
{
	struct vmap_area *va;
	struct rb_node *n;
	unsigned long addr;
	struct vmap_area *first;

	BUG_ON(!size);
	BUG_ON(offset_in_page(size));

	va = get_next_vmap_area();
	if (unlikely(!va))
		return ERR_PTR(-ENOMEM);

	spin_lock(&vmap_area_lock);

	/*
	 * Invalidate cache if we have more permissive parameters.
	 * cached_hole_size notes the largest hole noticed _below_
	 * the vmap_area cached in free_vmap_cache: if size fits
	 * into that hole, we want to scan from vstart to reuse
	 * the hole instead of allocating above free_vmap_cache.
	 * Note that __free_vmap_area may update free_vmap_cache
	 * without updating cached_hole_size or cached_align.
	 */
	if (!free_vmap_cache ||
			size < cached_hole_size ||
			vstart < cached_vstart ||
			align < cached_align) {
nocache:
		cached_hole_size = 0;
		free_vmap_cache = NULL;
	}
	/* record if we encounter less permissive parameters */
	cached_vstart = vstart;
	cached_align = align;

	/* find starting point for our search */
	if (free_vmap_cache) {
		first = rb_entry(free_vmap_cache, struct vmap_area, rb_node);
		addr = ALIGN(first->va_end, align);
		if (addr < vstart)
			goto nocache;
		if (addr + size < addr)
			goto overflow;
	} else {
		addr = ALIGN(vstart, align);
		if (addr + size < addr)
			goto overflow;

		n = vmap_area_root.rb_node;
		first = NULL;

		while (n) {
			struct vmap_area *tmp;
			tmp = rb_entry(n, struct vmap_area, rb_node);
			if (tmp->va_end >= addr) {
				first = tmp;
				if (tmp->va_start <= addr)
					break;
				n = n->rb_left;
			} else
				n = n->rb_right;
		}

		if (!first)
			goto found;
	}

	/* from the starting point, walk areas until a suitable hole is found */
	while (addr + size > first->va_start && addr + size <= vend) {
		if (addr + cached_hole_size < first->va_start)
			cached_hole_size = first->va_start - addr;
		addr = ALIGN(first->va_end, align);
		if (addr + size < addr)
			goto overflow;

		if (list_is_last(&first->list, &vmap_area_list))
			goto found;

		first = list_next_entry(first, list);
	}

found:
	if (addr + size > vend)
		goto overflow;

	va->va_start = addr;
	va->va_end = addr + size;
	va->flags = 0;
	__insert_vmap_area(va);
	free_vmap_cache = &va->rb_node;
	spin_unlock(&vmap_area_lock);

	BUG_ON(!IS_ALIGNED(va->va_start, align));
	BUG_ON(va->va_start < vstart);
	BUG_ON(va->va_end > vend);

	return va;

overflow:
	spin_unlock(&vmap_area_lock);

	free_vmap_area(va);
	return ERR_PTR(-EBUSY);
}

static void setup_vmalloc_vm(struct vm_struct *vm, struct vmap_area *va,
			      unsigned long flags, const void *caller)
{
	spin_lock(&vmap_area_lock);
	vm->flags = flags;
	vm->addr = (void *)va->va_start;
	vm->size = va->va_end - va->va_start;
	vm->caller = caller;
	va->vm = vm;
	va->flags |= VM_VM_AREA;
	spin_unlock(&vmap_area_lock);
}

static struct vm_struct *__get_vm_area_node(unsigned long size,
		unsigned long align, unsigned long flags, unsigned long start,
		unsigned long end, int node, gfp_t gfp_mask, const void *caller)
{
	struct vmap_area *va;
	struct vm_struct *area;

	size = PAGE_ALIGN(size);
	if (unlikely(!size))
		return NULL;

	if (flags & VM_IOREMAP)
		align = 1ul << clamp_t(int, get_count_order_long(size),
				       PAGE_SHIFT, IOREMAP_MAX_ORDER);

	area = get_next_vm_struct();
	if (unlikely(!area))
		return NULL;

	if (!(flags & VM_NO_GUARD))
		size += PAGE_SIZE;

	va = alloc_vmap_area(size, align, start, end, node, gfp_mask);
	if (IS_ERR(va)) {
		free_vm_struct(area);
		return NULL;
	}

	setup_vmalloc_vm(area, va, flags, caller);

	return area;
}

struct vm_struct *__get_vm_area(unsigned long size, unsigned long flags,
				unsigned long start, unsigned long end)
{
	return __get_vm_area_node(size, 1, flags, start, end, NUMA_NO_NODE,
				  GFP_KERNEL, __builtin_return_address(0));
}

struct vm_struct *__get_vm_area_caller(unsigned long size, unsigned long flags,
				       unsigned long start, unsigned long end,
				       const void *caller)
{
	return __get_vm_area_node(size, 1, flags, start, end, NUMA_NO_NODE,
				  GFP_KERNEL, caller);
}

/**
 *	get_vm_area  -  reserve a contiguous kernel virtual area
 *	@size:		size of the area
 *	@flags:		%VM_IOREMAP for I/O mappings or VM_ALLOC
 *
 *	Search an area of @size in the kernel virtual mapping area,
 *	and reserved it for out purposes.  Returns the area descriptor
 *	on success or %NULL on failure.
 */
struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
{
	return __get_vm_area_node(size, 1, flags, VMALLOC_START, VMALLOC_END,
				  NUMA_NO_NODE, GFP_KERNEL,
				  __builtin_return_address(0));
}

struct vm_struct *get_vm_area_caller(unsigned long size, unsigned long flags,
				const void *caller)
{
	return __get_vm_area_node(size, 1, flags, VMALLOC_START, VMALLOC_END,
				  NUMA_NO_NODE, GFP_KERNEL, caller);
}

static struct vmap_area *find_vmap_area(unsigned long addr)
{
	struct vmap_area *va;

	spin_lock(&vmap_area_lock);
	va = __find_vmap_area(addr);
	spin_unlock(&vmap_area_lock);

	return va;
}

/**
 *	remove_vm_area  -  find and remove a continuous kernel virtual area
 *	@addr:		base address
 *
 *	Search for the kernel VM area starting at @addr, and remove it.
 *	This function returns the found VM area, but using it is NOT safe
 *	on SMP machines, except for its size or flags.
 */
struct vm_struct *remove_vm_area(const void *addr)
{
	struct vmap_area *va;

	va = find_vmap_area((unsigned long)addr);
	if (va && va->flags & VM_VM_AREA) {
		struct vm_struct *vm = va->vm;

		spin_lock(&vmap_area_lock);
		va->vm = NULL;
		va->flags &= ~VM_VM_AREA;
		spin_unlock(&vmap_area_lock);

		//free_unmap_vmap_area(va);

		return vm;
	}
	return NULL;
}

void free_vm_area(struct vm_struct *area)
{
	struct vm_struct *ret;
	ret = remove_vm_area(area->addr);
	BUG_ON(ret != area);
	free_vm_struct(area);
}

static struct vmap_area *node_to_va(struct rb_node *n)
{
	return rb_entry_safe(n, struct vmap_area, rb_node);
}

/**
 * pvm_find_next_prev - find the next and prev vmap_area surrounding @end
 * @end: target address
 * @pnext: out arg for the next vmap_area
 * @pprev: out arg for the previous vmap_area
 *
 * Returns: %true if either or both of next and prev are found,
 *	    %false if no vmap_area exists
 *
 * Find vmap_areas end addresses of which enclose @end.  ie. if not
 * NULL, *pnext->va_end > @end and *pprev->va_end <= @end.
 */
static bool pvm_find_next_prev(unsigned long end,
			       struct vmap_area **pnext,
			       struct vmap_area **pprev)
{
	struct rb_node *n = vmap_area_root.rb_node;
	struct vmap_area *va = NULL;

	while (n) {
		va = rb_entry(n, struct vmap_area, rb_node);
		if (end < va->va_end)
			n = n->rb_left;
		else if (end > va->va_end)
			n = n->rb_right;
		else
			break;
	}

	if (!va)
		return false;

	if (va->va_end > end) {
		*pnext = va;
		*pprev = node_to_va(rb_prev(&(*pnext)->rb_node));
	} else {
		*pprev = va;
		*pnext = node_to_va(rb_next(&(*pprev)->rb_node));
	}
	return true;
}

/**
 * pvm_determine_end - find the highest aligned address between two vmap_areas
 * @pnext: in/out arg for the next vmap_area
 * @pprev: in/out arg for the previous vmap_area
 * @align: alignment
 *
 * Returns: determined end address
 *
 * Find the highest aligned address between *@pnext and *@pprev below
 * VMALLOC_END.  *@pnext and *@pprev are adjusted so that the aligned
 * down address is between the end addresses of the two vmap_areas.
 *
 * Please note that the address returned by this function may fall
 * inside *@pnext vmap_area.  The caller is responsible for checking
 * that.
 */
static unsigned long pvm_determine_end(struct vmap_area **pnext,
				       struct vmap_area **pprev,
				       unsigned long align)
{
	const unsigned long vmalloc_end = VMALLOC_END & ~(align - 1);
	unsigned long addr;

	if (*pnext)
		addr = min((*pnext)->va_start & ~(align - 1), vmalloc_end);
	else
		addr = vmalloc_end;

	while (*pprev && (*pprev)->va_end > addr) {
		*pnext = *pprev;
		*pprev = node_to_va(rb_prev(&(*pnext)->rb_node));
	}

	return addr;
}

/**
 * pcpu_get_vm_areas - allocate vmalloc areas for percpu allocator
 * @offsets: array containing offset of each area
 * @sizes: array containing size of each area
 * @nr_vms: the number of areas to allocate
 * @align: alignment, all entries in @offsets and @sizes must be aligned to this
 *
 * Returns: kmalloc'd vm_struct pointer array pointing to allocated
 *	    vm_structs on success, %NULL on failure
 *
 * Percpu allocator wants to use congruent vm areas so that it can
 * maintain the offsets among percpu areas.  This function allocates
 * congruent vmalloc areas for it with GFP_KERNEL.  These areas tend to
 * be scattered pretty far, distance between two areas easily going up
 * to gigabytes.  To avoid interacting with regular vmallocs, these
 * areas are allocated from top.
 *
 * Despite its complicated look, this allocator is rather simple.  It
 * does everything top-down and scans areas from the end looking for
 * matching slot.  While scanning, if any of the areas overlaps with
 * existing vmap_area, the base address is pulled down to fit the
 * area.  Scanning is repeated till all the areas fit and then all
 * necessary data structres are inserted and the result is returned.
 */
struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
				     const size_t *sizes, int nr_vms,
				     size_t align)
{
	const unsigned long vmalloc_start = ALIGN(VMALLOC_START, align);
	const unsigned long vmalloc_end = VMALLOC_END & ~(align - 1);
	struct vmap_area **vas, *prev, *next;
	struct vm_struct **vms;
	int area, area2, last_area, term_area;
	unsigned long base, start, end, last_end;

	/* verify parameters and allocate data structures */
	BUG_ON(offset_in_page(align) || !is_power_of_2(align));
	for (last_area = 0, area = 0; area < nr_vms; area++) {
		start = offsets[area];
		end = start + sizes[area];

		/* is everything aligned properly? */
		BUG_ON(!IS_ALIGNED(offsets[area], align));
		BUG_ON(!IS_ALIGNED(sizes[area], align));

		/* detect the area with the highest address */
		if (start > offsets[last_area])
			last_area = area;

		for (area2 = 0; area2 < nr_vms; area2++) {
			unsigned long start2 = offsets[area2];
			unsigned long end2 = start2 + sizes[area2];

			if (area2 == area)
				continue;

			BUG_ON(start2 >= start && start2 < end);
			BUG_ON(end2 <= end && end2 > start);
		}
	}
	last_end = offsets[last_area] + sizes[last_area];

	if (vmalloc_end - vmalloc_start < last_end) {
		WARN_ON(true);
		return NULL;
	}

	vms = kcalloc(nr_vms, sizeof(vms[0]), GFP_KERNEL);
	vas = kcalloc(nr_vms, sizeof(vas[0]), GFP_KERNEL);
	if (!vas || !vms)
		goto err_free2;

	for (area = 0; area < nr_vms; area++) {
		vas[area] = kzalloc(sizeof(struct vmap_area), GFP_KERNEL);
		vms[area] = kzalloc(sizeof(struct vm_struct), GFP_KERNEL);
		if (!vas[area] || !vms[area])
			goto err_free;
	}

	spin_lock(&vmap_area_lock);

	/* start scanning - we scan from the top, begin with the last area */
	area = term_area = last_area;
	start = offsets[area];
	end = start + sizes[area];

	if (!pvm_find_next_prev(vmap_area_pcpu_hole, &next, &prev)) {
		base = vmalloc_end - last_end;
		goto found;
	}
	base = pvm_determine_end(&next, &prev, align) - end;

	while (true) {
		BUG_ON(next && next->va_end <= base + end);
		BUG_ON(prev && prev->va_end > base + end);

		/*
		 * base might have underflowed, add last_end before
		 * comparing.
		 */
		if (base + last_end < vmalloc_start + last_end) {
			spin_unlock(&vmap_area_lock);
			goto err_free;
		}

		/*
		 * If next overlaps, move base downwards so that it's
		 * right below next and then recheck.
		 */
		if (next && next->va_start < base + end) {
			base = pvm_determine_end(&next, &prev, align) - end;
			term_area = area;
			continue;
		}

		/*
		 * If prev overlaps, shift down next and prev and move
		 * base so that it's right below new next and then
		 * recheck.
		 */
		if (prev && prev->va_end > base + start)  {
			next = prev;
			prev = node_to_va(rb_prev(&next->rb_node));
			base = pvm_determine_end(&next, &prev, align) - end;
			term_area = area;
			continue;
		}

		/*
		 * This area fits, move on to the previous one.  If
		 * the previous one is the terminal one, we're done.
		 */
		area = (area + nr_vms - 1) % nr_vms;
		if (area == term_area)
			break;
		start = offsets[area];
		end = start + sizes[area];
		pvm_find_next_prev(base + end, &next, &prev);
	}
found:
	/* we've found a fitting base, insert all va's */
	for (area = 0; area < nr_vms; area++) {
		struct vmap_area *va = vas[area];

		va->va_start = base + offsets[area];
		va->va_end = va->va_start + sizes[area];
		__insert_vmap_area(va);
	}

	vmap_area_pcpu_hole = base + offsets[last_area];

	spin_unlock(&vmap_area_lock);

	/* insert all vm's */
	for (area = 0; area < nr_vms; area++)
		setup_vmalloc_vm(vms[area], vas[area], VM_ALLOC,
				 pcpu_get_vm_areas);

	kfree(vas);
	return vms;

err_free:
	for (area = 0; area < nr_vms; area++) {
		kfree(vas[area]);
		kfree(vms[area]);
	}
err_free2:
	kfree(vas);
	kfree(vms);
	return NULL;
}

/**
 * pcpu_free_vm_areas - free vmalloc areas for percpu allocator
 * @vms: vm_struct pointer array returned by pcpu_get_vm_areas()
 * @nr_vms: the number of allocated areas
 *
 * Free vm_structs and the array allocated by pcpu_get_vm_areas().
 */
void pcpu_free_vm_areas(struct vm_struct **vms, int nr_vms)
{
	int i;

	for (i = 0; i < nr_vms; i++)
		free_vm_area(vms[i]);
	kfree(vms);
}

/*
 * Walk a vmap address to the struct page it maps.
 */
struct page *vmalloc_to_page(const void *vmalloc_addr)
{
	unsigned long addr = (unsigned long) vmalloc_addr;
	struct page *page = NULL;
	pgd_t *pgd = pgd_offset_k(addr);

	BUG_ON(!is_vmalloc_addr(vmalloc_addr));

	if (!pgd_none(*pgd)) {
		pud_t *pud = pud_offset(pgd, addr);
		if (!pud_none(*pud)) {
			pmd_t *pmd = pmd_offset(pud, addr);
			if (!pmd_none(*pmd)) {
				pte_t *ptep, pte;

				ptep = pte_offset_kernel(pmd, addr);
				pte = *ptep;
				if (pte_present(pte))
					page = pte_page(pte);
			}
		}
	}
	return page;
}

static void vunmap_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end)
{
	pte_t *pte;

	pte = pte_offset_kernel(pmd, addr);
	do {
		pte_t ptent = ptep_get_and_clear(addr, pte);
		WARN_ON(!pte_none(ptent) && !pte_present(ptent));
	} while (pte++, addr += PAGE_SIZE, addr != end);
}

static void vunmap_pmd_range(pud_t *pud, unsigned long addr, unsigned long end)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		vunmap_pte_range(pmd, addr, next);
	} while (pmd++, addr = next, addr != end);
}

static void vunmap_pud_range(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		vunmap_pmd_range(pud, addr, next);
	} while (pud++, addr = next, addr != end);
}

static void vunmap_page_range(unsigned long addr, unsigned long end)
{
	pgd_t *pgd;
	unsigned long next;

	BUG_ON(addr >= end);
	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		vunmap_pud_range(pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
}

static int vmap_pte_range(pmd_t *pmd, unsigned long addr,
		unsigned long end, pgprot_t prot, struct page **pages, int *nr)
{
	pte_t *pte;

	/*
	 * nr is a running index into the array which helps higher level
	 * callers keep track of where we're up to.
	 */

	pte = pte_alloc_kernel(pmd, addr);
	if (!pte)
		return -ENOMEM;
	do {
		struct page *page = pages[*nr];

		if (WARN_ON(!pte_none(*pte)))
			return -EBUSY;
		if (WARN_ON(!page))
			return -ENOMEM;
		pte_set(pte, mk_pte(page, prot));
		(*nr)++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
	return 0;
}

static int vmap_pmd_range(pud_t *pud, unsigned long addr,
		unsigned long end, pgprot_t prot, struct page **pages, int *nr)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_alloc(&init_mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);
		if (vmap_pte_range(pmd, addr, next, prot, pages, nr))
			return -ENOMEM;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

static int vmap_pud_range(pgd_t *pgd, unsigned long addr,
		unsigned long end, pgprot_t prot, struct page **pages, int *nr)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_alloc(&init_mm, pgd, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		if (vmap_pmd_range(pud, addr, next, prot, pages, nr))
			return -ENOMEM;
	} while (pud++, addr = next, addr != end);
	return 0;
}

/*
 * Set up page tables in kva (addr, end). The ptes shall have prot "prot", and
 * will have pfns corresponding to the "pages" array.
 *
 * Ie. pte at addr+N*PAGE_SIZE shall point to pfn corresponding to pages[N]
 */
static int vmap_page_range_noflush(unsigned long start, unsigned long end,
				   pgprot_t prot, struct page **pages)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long addr = start;
	int err = 0;
	int nr = 0;

	BUG_ON(addr >= end);
	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		err = vmap_pud_range(pgd, addr, next, prot, pages, &nr);
		if (err)
			return err;
	} while (pgd++, addr = next, addr != end);

	return nr;
}

static int vmap_page_range(unsigned long start, unsigned long end,
			   pgprot_t prot, struct page **pages)
{
	int ret;

	ret = vmap_page_range_noflush(start, end, prot, pages);

	return ret;
}

int map_vm_area(struct vm_struct *area, pgprot_t prot, struct page ***pages)
{
	unsigned long addr = (unsigned long)area->addr;
	unsigned long end = addr + get_vm_area_size(area);
	int err;

	err = vmap_page_range(addr, end, prot, *pages);
	if (err > 0) {
		*pages += err;
		err = 0;
	}

	return err;
}

void vfree(const void *addr)
{
// XXX TODO
}

static void __vunmap(const void *addr, int deallocate_pages)
{
	struct vm_struct *area;

	if (!addr)
		return;

	if (WARN(!PAGE_ALIGNED(addr), "Trying to vfree() bad address (%p)\n",
			addr))
		return;

	area = remove_vm_area(addr);
	if (unlikely(!area)) {
		WARN(1, KERN_ERR "Trying to vfree() nonexistent vm area (%p)\n",
				addr);
		return;
	}

	if (deallocate_pages) {
		int i;

		for (i = 0; i < area->nr_pages; i++) {
			struct page *page = area->pages[i];

			BUG_ON(!page);
			__free_page(page);
		}

		if (area->flags & VM_VPAGES)
			vfree(area->pages);
//		else
//			kfree(area->pages);
	}

//	kfree(area);
	return;
}
 
/**
 *	vunmap  -  release virtual mapping obtained by vmap()
 *	@addr:		memory base address
 *
 *	Free the virtually contiguous memory area starting at @addr,
 *	which was created from the page array passed to vmap().
 *
 *	Must not be called in interrupt context.
 */
void vunmap(const void *addr)
{
	if (addr)
		__vunmap(addr, 0);
}

/**
 *      vmap  -  map an array of pages into virtually contiguous space
 *      @pages:         array of page pointers
 *      @count:         number of pages to map
 *      @flags:         vm_area->flags
 *      @prot:          page protection for the mapping
 *
 *      Maps @count pages from @pages into contiguous kernel virtual
 *      space.
 */
void *vmap(struct page **pages, unsigned int count,
		unsigned long flags, pgprot_t prot)
{
	struct vm_struct *area;

	area = get_vm_area_caller((count << PAGE_SHIFT), flags,
			__builtin_return_address(0));
	if (!area)
		return NULL;

	if (map_vm_area(area, prot, &pages)) {
		vunmap(area->addr);
		return NULL;
	}

	return area->addr;
}

/**
 * map_kernel_range_noflush - map kernel VM area with the specified pages
 * @addr: start of the VM area to map
 * @size: size of the VM area to map
 * @prot: page protection flags to use
 * @pages: pages to map
 *
 * Map PFN_UP(@size) pages at @addr.  The VM area @addr and @size
 * specify should have been allocated using get_vm_area() and its
 * friends.
 *
 * NOTE:
 * This function does NOT do any cache flushing.  The caller is
 * responsible for calling flush_cache_vmap() on to-be-mapped areas
 * before calling this function.
 *
 * RETURNS:
 * The number of pages mapped on success, -errno on failure.
 */
int map_kernel_range_noflush(unsigned long addr, unsigned long size,
			     pgprot_t prot, struct page **pages)
{
	return vmap_page_range_noflush(addr, addr + size, prot, pages);
}

/**
 * unmap_kernel_range_noflush - unmap kernel VM area
 * @addr: start of the VM area to unmap
 * @size: size of the VM area to unmap
 *
 * Unmap PFN_UP(@size) pages at @addr.  The VM area @addr and @size
 * specify should have been allocated using get_vm_area() and its
 * friends.
 *
 * NOTE:
 * This function does NOT do any cache flushing.  The caller is
 * responsible for calling flush_cache_vunmap() on to-be-mapped areas
 * before calling this function and flush_tlb_kernel_range() after.
 */
void unmap_kernel_range_noflush(unsigned long addr, unsigned long size)
{
	vunmap_page_range(addr, addr + size);
}
