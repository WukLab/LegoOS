/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/err.h>
#include <lego/numa.h>
#include <lego/list.h>
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

/* TODO: Use kmalloc and kfree once slab is built */
static struct vmap_area *get_next_vmap_area(void)
{
	return (struct vmap_area *)((void *)get_zeroed_page(GFP_KERNEL));
}

static void free_vmap_area(struct vmap_area *va)
{
	free_page((unsigned long)va);
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
