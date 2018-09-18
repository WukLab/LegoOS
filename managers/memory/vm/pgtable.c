/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/comp_memory.h>

#include <memory/vm.h>
#include <memory/vm-pgtable.h>

#define PGALLOC_GFP	(GFP_KERNEL | __GFP_ZERO)

static inline bool lego_pgtable_page_ctor(struct page *page)
{
	if (!ptlock_init(page))
		return false;
	return true;
}

static inline void lego_pgtable_page_dtor(struct page *page)
{
	pte_lock_deinit(page);
}

/*
 * lego_pxd_alloc_one
 * This set of functions are used to allocate a pgtable page.
 */
static inline pud_t *lego_pud_alloc_one(void)
{
	return (pud_t *)__get_free_page(PGALLOC_GFP);
}

static inline pmd_t *lego_pmd_alloc_one(void)
{
	struct page *page;

	page = alloc_pages(PGALLOC_GFP, 0);
	if (!page)
		return NULL;
	if (!lego_pgtable_pmd_page_ctor(page)) {
		__free_pages(page, 0);
		return NULL;
	}
	return (pmd_t *)page_address(page);
}

static inline pte_t *lego_pte_alloc_one(void)
{
	struct page *page;

	page = alloc_pages(PGALLOC_GFP, 0);
	if (!page)
		return NULL;
	if (!lego_pgtable_page_ctor(page)) {
		__free_pages(page, 0);
		return NULL;
	}
	return (pte_t *)page_address(page);
}

/*
 * lego_pxd_free
 * This set functions are used to free the pgtable page
 */
static inline void lego_pud_free(pud_t *pud)
{
	BUG_ON((unsigned long)pud & (PAGE_SIZE-1));
	free_page((unsigned long)pud);
}

static inline void lego_pmd_free(pmd_t *pmd)
{
	BUG_ON((unsigned long)pmd & (PAGE_SIZE-1));
	lego_pgtable_pmd_page_dtor(virt_to_page(pmd));
	free_page((unsigned long)pmd);
}

static inline void lego_pte_free(pte_t *pte)
{
	BUG_ON((unsigned long)pte & (PAGE_SIZE-1));
	lego_pgtable_page_dtor(virt_to_page(pte));
	free_page((unsigned long)pte);
}

static inline void __lego_pte_free(struct page *token)
{
	__free_page(token);
}

/*
 * lego_pxd_populate
 * All level page table entries are filled with
 * _virtual address_ of the next level pgtable page.
 */
static inline void lego_pgd_populate(pgd_t *pgd, pud_t *pud)
{
	pgd_set(pgd, __pgd(_PAGE_TABLE | (unsigned long)pud));
}

static inline void lego_pud_populate(pud_t *pud, pmd_t *pmd)
{
	pud_set(pud, __pud(_PAGE_TABLE | (unsigned long)pmd));
}

static inline void lego_pmd_populate(pmd_t *pmd, pte_t *pte)
{
	pmd_set(pmd, __pmd(_PAGE_TABLE | (unsigned long)pte));
}

/*
 * __lego_pxd_alloc
 * This set of functions will allocate a pgtable page, and populate its
 * kernel virtual address in the upper layer pgtable entry.
 *
 * pgd/pud populate are protected by mm's big page_table_lock.
 * pmd populate is protected by per PMD pgtable page lock, in the hope of
 * increase certain amount of parallisim.
 */
int __lego_pud_alloc(struct lego_mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	pud_t *new = lego_pud_alloc_one();
	if (!new)
		return -ENOMEM;

	smp_wmb();

	spin_lock(&mm->lego_page_table_lock);
	if (pgd_present(*pgd))
		 /* Another has populated it */
		lego_pud_free(new);
	else
		lego_pgd_populate(pgd, new);
	spin_unlock(&mm->lego_page_table_lock);
	return 0;
}

int __lego_pmd_alloc(struct lego_mm_struct *mm, pud_t *pud, unsigned long address)
{
	pmd_t *new = lego_pmd_alloc_one();
	if (!new)
		return -ENOMEM;

	smp_wmb();

	spin_lock(&mm->lego_page_table_lock);
	if (pud_present(*pud))
		 /* Another has populated it */
		lego_pmd_free(new);
	else
		lego_pud_populate(pud, new);
	spin_unlock(&mm->lego_page_table_lock);
	return 0;
}

int __lego_pte_alloc(struct lego_mm_struct *mm, pmd_t *pmd, unsigned long address)
{
	spinlock_t *ptl;
	pte_t *new = lego_pte_alloc_one();
	if (!new)
		return -ENOMEM;

	smp_wmb();

	ptl = lego_pmd_lock(mm, pmd);
	if (likely(pmd_none(*pmd))) {
		lego_pmd_populate(pmd, new);
		new = NULL;
	}
	spin_unlock(ptl);
	if (new)
		lego_pte_free(new);
	return 0;
}

static void free_pte_range(struct lego_mm_struct *mm,
			   pmd_t *pmd, unsigned long addr)
{
	struct page *token = lego_pmd_page(*pmd);

	pmd_clear(pmd);
	__lego_pte_free(token);
}

static inline void free_pmd_range(struct lego_mm_struct *mm, pud_t *pud,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pmd_t *pmd;
	unsigned long next;
	unsigned long start;

	start = addr;
	pmd = lego_pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none(*pmd))
			continue;
		free_pte_range(mm, pmd, addr);
	} while (pmd++, addr = next, addr != end);

	start &= PUD_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= PUD_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	pmd = lego_pmd_offset(pud, start);
	pud_clear(pud);
	lego_pmd_free(pmd);
}

static inline void free_pud_range(struct lego_mm_struct *mm, pgd_t *pgd,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pud_t *pud;
	unsigned long next;
	unsigned long start;

	start = addr;
	pud = lego_pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none(*pud))
			continue;
		free_pmd_range(mm, pud, addr, next, floor, ceiling);
	} while (pud++, addr = next, addr != end);

	start &= PGDIR_MASK;
	if (start < floor)
		return;
	if (ceiling) {
		ceiling &= PGDIR_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		return;

	pud = lego_pud_offset(pgd, start);
	pgd_clear(pgd);
	lego_pud_free(pud);
}

/*
 * This function frees user-level page tables of a process.
 *
 * Note: this doesn't free the actual pages themselves. That
 * has been handled earlier when unmapping all the memory regions.
 */
void lego_free_pgd_range(struct lego_mm_struct *mm,
			 unsigned long addr, unsigned long end,
			 unsigned long floor, unsigned long ceiling)
{
	pgd_t *pgd;
	unsigned long next;

	/*
	 * The next few lines have given us lots of grief...
	 *
	 * Why are we testing PMD* at this top level?  Because often
	 * there will be no work to do at all, and we'd prefer not to
	 * go all the way down to the bottom just to discover that.
	 *
	 * Why all these "- 1"s?  Because 0 represents both the bottom
	 * of the address space and the top of it (using -1 for the
	 * top wouldn't help much: the masks would do the wrong thing).
	 * The rule is that addr 0 and floor 0 refer to the bottom of
	 * the address space, but end 0 and ceiling 0 refer to the top
	 * Comparisons need to use "end - 1" and "ceiling - 1" (though
	 * that end 0 case should be mythical).
	 *
	 * Wherever addr is brought up or ceiling brought down, we must
	 * be careful to reject "the opposite 0" before it confuses the
	 * subsequent tests.  But what about where end is brought down
	 * by PMD_SIZE below? no, end can't go down to 0 there.
	 *
	 * Whereas we round start (addr) and ceiling down, by different
	 * masks at different levels, in order to test whether a table
	 * now has no other vmas using it, so can be freed, we don't
	 * bother to round floor or end up - the tests don't need that.
	 */

	addr &= PMD_MASK;
	if (addr < floor) {
		addr += PMD_SIZE;
		if (!addr)
			return;
	}
	if (ceiling) {
		ceiling &= PMD_MASK;
		if (!ceiling)
			return;
	}
	if (end - 1 > ceiling - 1)
		end -= PMD_SIZE;
	if (addr > end - 1)
		return;

	pgd = lego_pgd_offset(mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none(*pgd))
			continue;
		free_pud_range(mm, pgd, addr, next, floor, ceiling);
	} while (pgd++, addr = next, addr != end);
}

void lego_free_pgtables(struct vm_area_struct *vma,
			unsigned long floor, unsigned long ceiling)
{
	struct lego_mm_struct *mm = vma->vm_mm;

	while (vma) {
		struct vm_area_struct *next = vma->vm_next;
		unsigned long addr = vma->vm_start;

		lego_free_pgd_range(mm, addr, vma->vm_end,
			floor, next? next->vm_start: ceiling);
		vma = next;
	}
}

static inline int
lego_copy_one_pte(struct lego_mm_struct *dst_mm, struct lego_mm_struct *src_mm,
		pte_t *dst_pte, pte_t *src_pte, struct vm_area_struct *vma,
		unsigned long addr)
{
	unsigned long vm_flags = vma->vm_flags;
	pte_t pte = *src_pte;
	struct page *page;
	unsigned long virt;

	/*
	 * PTE contains position in swap or file?
	 * Lego does not have any swap now, so skip.
	 */
	if (unlikely(!pte_present(pte)))
		goto pte_set;

	/*
	 * If it's a COW mapping, write protect it both
	 * in the parent and the child
	 */
	if (is_cow_mapping(vm_flags)) {
		ptep_set_wrprotect(src_pte);
		pte = pte_wrprotect(pte);
	}

	/*
	 * If it's a shared mapping, mark it clean in
	 * the child:
	 */
	if (vm_flags & VM_SHARED)
		pte = pte_mkclean(pte);
	pte = pte_mkold(pte);

	virt = lego_pte_to_virt(pte);
	page = virt_to_page(virt);
	if (page)
		get_page(page);

pte_set:
	pte_set(dst_pte, pte);
	return 0;
}

static int lego_copy_pte_range(struct lego_mm_struct *dst_mm,
			  struct lego_mm_struct *src_mm,
		   	  pmd_t *dst_pmd, pmd_t *src_pmd,
			  struct vm_area_struct *vma,
		   	  unsigned long addr, unsigned long end)
{
	pte_t *orig_src_pte, *orig_dst_pte;
	pte_t *src_pte, *dst_pte;
	spinlock_t *src_ptl, *dst_ptl;
	int ret;

	dst_pte = lego_pte_alloc(dst_mm, dst_pmd, addr);
	if (!dst_pte)
		return -ENOMEM;
	dst_ptl = lego_pte_lockptr(dst_mm, dst_pmd);
	spin_lock(dst_ptl);

	src_pte = lego_pte_offset(src_pmd, addr);
	src_ptl = lego_pte_lockptr(src_mm, src_pmd);

	if (src_ptl != dst_ptl)
		spin_lock(src_ptl);

	orig_src_pte = src_pte;
	orig_dst_pte = dst_pte;

	ret = 0;
	do {
		if (pte_none(*src_pte))
			continue;
		if (lego_copy_one_pte(dst_mm, src_mm, dst_pte, src_pte, vma, addr)) {
			ret = -ENOMEM;
			break;
		}
	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr != end);

	if (src_ptl != dst_ptl)
		spin_unlock(src_ptl);
	spin_unlock(dst_ptl);

	return 0;
}

static inline int lego_copy_pmd_range(struct lego_mm_struct *dst_mm,
				 struct lego_mm_struct *src_mm,
				 pud_t *dst_pud, pud_t *src_pud,
				 struct vm_area_struct *vma,
				 unsigned long addr, unsigned long end)
{
	pmd_t *src_pmd, *dst_pmd;
	unsigned long next;

	dst_pmd = lego_pmd_alloc(dst_mm, dst_pud, addr);
	if (!dst_pmd)
		return -ENOMEM;
	src_pmd = lego_pmd_offset(src_pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none(*src_pmd))
			continue;
		if (lego_copy_pte_range(dst_mm, src_mm, dst_pmd, src_pmd,
						vma, addr, next))
			return -ENOMEM;
	} while (dst_pmd++, src_pmd++, addr = next, addr != end);
	return 0;
}

static inline int lego_copy_pud_range(struct lego_mm_struct *dst_mm,
				 struct lego_mm_struct *src_mm,
				 pgd_t *dst_pgd, pgd_t *src_pgd,
				 struct vm_area_struct *vma,
				 unsigned long addr, unsigned long end)
{
	pud_t *src_pud, *dst_pud;
	unsigned long next;

	dst_pud = lego_pud_alloc(dst_mm, dst_pgd, addr);
	if (!dst_pud)
		return -ENOMEM;
	src_pud = lego_pud_offset(src_pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none(*src_pud))
			continue;
		if (lego_copy_pmd_range(dst_mm, src_mm, dst_pud, src_pud,
						vma, addr, next))
			return -ENOMEM;
	} while (dst_pud++, src_pud++, addr = next, addr != end);
	return 0;
}

/*
 * This function is called during fork() time.
 * It will copy the vma page table mapping from source mm to destination mm.
 * It will make writable && non-shared pages RO for both mm (for COW).
 */
int lego_copy_page_range(struct lego_mm_struct *dst, struct lego_mm_struct *src,
			 struct vm_area_struct *vma)
{
	pgd_t *src_pgd, *dst_pgd;
	unsigned long next;
	unsigned long addr = vma->vm_start;
	unsigned long end = vma->vm_end;
	int ret;

	ret = 0;
	dst_pgd = lego_pgd_offset(dst, addr);
	src_pgd = lego_pgd_offset(src, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none(*src_pgd))
			continue;
		if (unlikely(lego_copy_pud_range(dst, src, dst_pgd, src_pgd,
					    vma, addr, next))) {
			ret = -ENOMEM;
			break;
		}
	} while (dst_pgd++, src_pgd++, addr = next, addr != end);

	return ret;
}

/*
 * And we don't need to flush TLB here
 * because we are doing emulation at memory manager.
 */
static unsigned long
zap_pte_range(struct vm_area_struct *vma, pmd_t *pmd,
	      unsigned long addr, unsigned long end)
{
	struct lego_mm_struct *mm = vma->vm_mm;
	spinlock_t *ptl;
	pte_t *start_pte;
	pte_t *pte;
	unsigned long page;

	start_pte = lego_pte_offset_lock(mm, pmd, addr, &ptl);
	pte = start_pte;

	do {
		pte_t ptent = *pte;

		if (pte_none(ptent))
			continue;

		if (pte_present(ptent)) {
			ptent = ptep_get_and_clear_full(pte);

			/*
			 * Yes, viginia. We encoded VPN into PTE.
			 * Check comments at handle_lego_mm_fault.
			 */
			page = lego_pte_to_virt(ptent);
			free_page(page);
			continue;
		}
		pte_clear(pte);
	} while (pte++, addr += PAGE_SIZE, addr != end);

	spin_unlock(ptl);

	return addr;
}

static inline unsigned long
zap_pmd_range(struct vm_area_struct *vma, pud_t *pud,
	      unsigned long addr, unsigned long end)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = lego_pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none(*pmd))
			continue;
		next = zap_pte_range(vma, pmd, addr, next);
	} while (pmd++, addr = next, addr != end);

	return addr;
}

static inline unsigned long
zap_pud_range(struct vm_area_struct *vma, pgd_t *pgd,
	      unsigned long addr, unsigned long end)
{
	pud_t *pud;
	unsigned long next;

	pud = lego_pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none(*pud))
			continue;
		next = zap_pmd_range(vma, pud, addr, next);
	} while (pud++, addr = next, addr != end);

	return addr;
}

void lego_unmap_page_range(struct vm_area_struct *vma,
			   unsigned long addr, unsigned long end)
{
	pgd_t *pgd;
	unsigned long next;

	BUG_ON(addr >= end);
	pgd = lego_pgd_offset(vma->vm_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none(*pgd))
			continue;
		next = zap_pud_range(vma, pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
}

static pmd_t *get_old_pmd(struct lego_mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	pgd = lego_pgd_offset(mm, addr);
	if (pgd_none(*pgd))
		return NULL;

	pud = lego_pud_offset(pgd, addr);
	if (pud_none(*pud))
		return NULL;

	pmd = lego_pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;

	return pmd;
}

static pmd_t *alloc_new_pmd(struct lego_mm_struct *mm, struct vm_area_struct *vma,
			    unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	pgd = lego_pgd_offset(mm, addr);
	pud = lego_pud_alloc(mm, pgd, addr);
	if (!pud)
		return NULL;

	pmd = lego_pmd_alloc(mm, pud, addr);
	if (!pmd)
		return NULL;

	return pmd;
}

static void move_ptes(struct vm_area_struct *vma, pmd_t *old_pmd,
		unsigned long old_addr, unsigned long old_end,
		struct vm_area_struct *new_vma, pmd_t *new_pmd,
		unsigned long new_addr)
{
	struct lego_mm_struct *mm = vma->vm_mm;
	pte_t *old_pte, *new_pte, pte;
	spinlock_t *old_ptl, *new_ptl;

	/*
	 * We don't have to worry about the ordering of src and dst
	 * pte locks because exclusive mmap_sem prevents deadlock.
	 */
	old_pte = lego_pte_offset_lock(mm, old_pmd, old_addr, &old_ptl);

	new_pte = lego_pte_offset(new_pmd, new_addr);
	new_ptl = lego_pte_lockptr(mm, new_pmd);
	if (new_ptl != old_ptl)
		spin_lock(new_ptl);

	for (; old_addr < old_end; old_pte++, old_addr += PAGE_SIZE,
				   new_pte++, new_addr += PAGE_SIZE) {
		if (pte_none(*old_pte))
			continue;

		pte = ptep_get_and_clear(old_addr, old_pte);
		pte_set(new_pte, pte);
	}

	if (new_ptl != old_ptl)
		spin_unlock(new_ptl);
	spin_unlock(old_ptl);
}

#define LATENCY_LIMIT	(64 * PAGE_SIZE)

unsigned long lego_move_page_tables(struct vm_area_struct *vma,
		unsigned long old_addr, struct vm_area_struct *new_vma,
		unsigned long new_addr, unsigned long len)
{
	unsigned long extent, next, old_end;
	pmd_t *old_pmd, *new_pmd;

	old_end = old_addr + len;

	for (; old_addr < old_end; old_addr += extent, new_addr += extent) {
		next = (old_addr + PMD_SIZE) & PMD_MASK;

		/* even if next overflowed, extent below will be ok */
		extent = next - old_addr;
		if (extent > old_end - old_addr)
			extent = old_end - old_addr;

		old_pmd = get_old_pmd(vma->vm_mm, old_addr);
		if (!old_pmd)
			continue;

		new_pmd = alloc_new_pmd(vma->vm_mm, vma, new_addr);
		if (!new_pmd)
			break;

		if (!lego_pte_alloc(new_vma->vm_mm, new_pmd, new_addr))
			break;

		next = (new_addr + PMD_SIZE) & PMD_MASK;
		if (extent > next - new_addr)
			extent = next - new_addr;
		if (extent > LATENCY_LIMIT)
			extent = LATENCY_LIMIT;

		move_ptes(vma, old_pmd, old_addr, old_addr + extent, new_vma,
			  new_pmd, new_addr);
	}

	return len + old_addr - old_end;	/* how much done */
}
