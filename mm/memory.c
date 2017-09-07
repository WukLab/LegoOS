/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgalloc.h>

#include <lego/mm.h>
#include <lego/bug.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/memblock.h>

#include <lego/comp_common.h>

#ifdef CONFIG_FLATMEM
struct pglist_data contig_page_data;
struct page *mem_map;
#endif

/*
 * Allocate page upper directory.
 * We've already handled the fast-path in-line.
 */
int __pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	pud_t *new = pud_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	barrier();

	spin_lock(&mm->page_table_lock);
	if (pgd_present(*pgd))		/* Another has populated it */
		pud_free(mm, new);
	else
		pgd_populate(mm, pgd, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}

/*
 * Allocate page middle directory.
 * We've already handled the fast-path in-line.
 */
int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	pmd_t *new = pmd_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	barrier();

	spin_lock(&mm->page_table_lock);
	if (!pud_present(*pud))
		pud_populate(mm, pud, new);
	else	/* Another has populated it */
		pmd_free(mm, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}

int __pte_alloc(struct mm_struct *mm, pmd_t *pmd, unsigned long address)
{
	pte_t *new = pte_alloc_one_kernel(mm, address);
	if (!new)
		return -ENOMEM;

	barrier();
	spin_lock(&mm->page_table_lock);
	if (!pmd_present(*pmd))
		pmd_populate_kernel(mm, pmd, new);
	else	/* Another has populated it */
		pte_free_kernel(mm, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}

int __pte_alloc_kernel(pmd_t *pmd, unsigned long address)
{
	pte_t *new = pte_alloc_one_kernel(&init_mm, address);
	if (!new)
		return -ENOMEM;

	barrier();

	spin_lock(&init_mm.page_table_lock);
	if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
		pmd_populate_kernel(&init_mm, pmd, new);
		new = NULL;
	}
	spin_unlock(&init_mm.page_table_lock);
	if (new)
		pte_free_kernel(&init_mm, new);
	return 0;
}

#ifdef CONFIG_COMP_PROCESSOR
/*
 * Only processor manager need those functions to manipulate
 * the emulated pgtable. Those functions work on user pgtable ranges.
 */

static void free_pte_range(struct mm_struct *mm, pmd_t *pmd,
			   unsigned long addr)
{
	struct page *token = pmd_pgtable(*pmd);

	pmd_clear(pmd);
	pte_free(mm, token);
}

static inline void free_pmd_range(struct mm_struct *mm, pud_t *pud,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pmd_t *pmd;
	unsigned long next;
	unsigned long start;

	start = addr;
	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
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

	pmd = pmd_offset(pud, start);
	pud_clear(pud);
	pmd_free(mm, pmd);
}

static inline void free_pud_range(struct mm_struct *mm, pgd_t *pgd,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pud_t *pud;
	unsigned long next;
	unsigned long start;

	start = addr;
	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
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

	pud = pud_offset(pgd, start);
	pgd_clear(pgd);
	pud_free(mm, pud);
}

/*
 * Clear all pgtable entries and free pgtable pages.
 *
 * Note: this doesn't free the actual pages themselves. That
 * has been handled earlier when unmapping all the memory regions.
 *
 * All pages used for pgtable are just normal pages. Unlike the actual
 * pages themselves, which are pcache cachelines who do not have any
 * associated `struct page'!
 */
void free_pgd_range(struct mm_struct *mm,
		    unsigned long __user addr, unsigned long __user end,
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

	pgd = pgd_offset(mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		free_pud_range(mm, pgd, addr, next, floor, ceiling);
	} while (pgd++, addr = next, addr != end);
}

static unsigned long
zap_pte_range(struct mm_struct *mm, pmd_t *pmd,
	      unsigned long addr, unsigned long end)
{
	spinlock_t *ptl;
	pte_t *start_pte;
	pte_t *pte;

	start_pte = pte_offset_lock(mm, pmd, addr, &ptl);
	pte = start_pte;

	/*
	 * TODO: pcache
	 * Hmm, all ptes point to pcache pages, which does not have
	 * a 'struct page' associated. We probaly need to call back
	 * to pcache code to update cacheline metadata.
	 */
	do {
		pte_t ptent = *pte;

		if (pte_none(ptent))
			continue;

		if (pte_present(ptent)) {
			ptent = ptep_get_and_clear_full(pte);
			continue;
		}

		pte_clear(pte);
	} while (pte++, addr += PAGE_SIZE, addr != end);

	spin_unlock(ptl);

	return addr;
}

static inline unsigned long
zap_pmd_range(struct mm_struct *mm, pud_t *pud,
	      unsigned long addr, unsigned long end)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		next = zap_pte_range(mm, pmd, addr, next);
	} while (pmd++, addr = next, addr != end);

	return addr;
}

static inline unsigned long
zap_pud_range(struct mm_struct *mm, pgd_t *pgd,
	      unsigned long addr, unsigned long end)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		next = zap_pmd_range(mm, pud, addr, next);
	} while (pud++, addr = next, addr != end);

	return addr;
}

/*
 * Unmap and free physical pages mapped to [@addr, @end).
 *
 * This function will free the physical pages themselves,
 * but it will NOT free the pages used for pgtable, which
 * is handled by free_pgd_range().
 *
 * Only PTEs are cleared. PGD, PUD, and PMD are not cleared.
 */
void unmap_page_range(struct mm_struct *mm,
		      unsigned long __user addr, unsigned long __user end)
{
	pgd_t *pgd;
	unsigned long next;

	BUG_ON(addr >= end);
	pgd = pgd_offset(mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		next = zap_pud_range(mm, pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
}

static inline int
copy_one_pte(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pte_t *dst_pte, pte_t *src_pte, struct p_vm_area_struct *vma,
		unsigned long addr)
{
	unsigned long vm_flags = vma->vm_flags;
	pte_t pte = *src_pte;

	/*
	 * PTE contains position in swap or file
	 * Lego does not have any swap now, so skip.
	 */
	if (unlikely(!pte_present(pte))) {
		WARN_ONCE(1, "No swap file, this case should NOT happen!");
		goto pte_set;
	}

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

	/*
	 * TODO:
	 * If we need rmap in memory component
	 * we need to increment 1 mapcount here!
	 */

pte_set:
	pte_set(dst_pte, pte);
	return 0;
}

static int copy_pte_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		   pmd_t *dst_pmd, pmd_t *src_pmd, struct p_vm_area_struct *vma,
		   unsigned long addr, unsigned long end)
{
	pte_t *orig_src_pte, *orig_dst_pte;
	pte_t *src_pte, *dst_pte;
	spinlock_t *src_ptl, *dst_ptl;
	int ret;

	dst_pte = pte_alloc_lock(dst_mm, dst_pmd, addr, &dst_ptl);
	if (!dst_pte)
		return -ENOMEM;

	src_pte = pte_offset(src_pmd, addr);
	src_ptl = pte_lockptr(src_mm, src_pmd);
	spin_lock(src_ptl);

	orig_src_pte = src_pte;
	orig_dst_pte = dst_pte;

	ret = 0;
	do {
		if (pte_none(*src_pte))
			continue;
		if (unlikely(copy_one_pte(dst_mm, src_mm, dst_pte, src_pte,
					  vma, addr))) {
			ret = -ENOMEM;
			break;
		}
	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr != end);

	spin_unlock(src_ptl);
	spin_unlock(dst_ptl);

	return ret;
}

static inline int copy_pmd_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pud_t *dst_pud, pud_t *src_pud, struct p_vm_area_struct *vma,
		unsigned long addr, unsigned long end)
{
	pmd_t *src_pmd, *dst_pmd;
	unsigned long next;

	dst_pmd = pmd_alloc(dst_mm, dst_pud, addr);
	if (!dst_pmd)
		return -ENOMEM;

	src_pmd = pmd_offset(src_pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(src_pmd))
			continue;
		if (unlikely(copy_pte_range(dst_mm, src_mm, dst_pmd, src_pmd,
						vma, addr, next)))
			return -ENOMEM;
	} while (dst_pmd++, src_pmd++, addr = next, addr != end);
	return 0;
}

static inline int copy_pud_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pgd_t *dst_pgd, pgd_t *src_pgd, struct p_vm_area_struct *vma,
		unsigned long addr, unsigned long end)
{
	pud_t *src_pud, *dst_pud;
	unsigned long next;

	dst_pud = pud_alloc(dst_mm, dst_pgd, addr);
	if (!dst_pud)
		return -ENOMEM;

	src_pud = pud_offset(src_pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(src_pud))
			continue;
		if (unlikely(copy_pmd_range(dst_mm, src_mm, dst_pud, src_pud,
						vma, addr, next)))
			return -ENOMEM;
	} while (dst_pud++, src_pud++, addr = next, addr != end);
	return 0;
}

/*
 * Copy one vm_area from one task to the other. Assumes the page tables
 * already present in the new task to be cleared in the whole range
 * covered by this vma.
 */
int copy_page_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		    struct p_vm_area_struct *vma)
{
	pgd_t *src_pgd, *dst_pgd;
	unsigned long next;
	unsigned long addr = vma->vm_start;
	unsigned long end = vma->vm_end;
	int ret;

	ret = 0;
	dst_pgd = pgd_offset(dst_mm, addr);
	src_pgd = pgd_offset(src_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(src_pgd))
			continue;
		if (unlikely(copy_pud_range(dst_mm, src_mm, dst_pgd, src_pgd,
					    vma, addr, next))) {
			ret = -ENOMEM;
			break;
		}
	} while (dst_pgd++, src_pgd++, addr = next, addr != end);

	return ret;
}

#endif /* CONFIG_COMP_PROCESSOR */
