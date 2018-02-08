/*
 * Copyright (c) 2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * NOTE:
 * Only processor manager need those functions to manipulate
 * the emulated pgtable. Those functions work on user pgtable ranges.
 */

#include <lego/mm.h>
#include <lego/sched.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/memblock.h>
#include <processor/pgtable.h>

#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>

#ifdef CONFIG_DEBUG_EMULATED_PGTABLE
#define pgtable_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
static inline void pgtable_debug(const char *fmt, ...) { }
#endif

static void free_pte_range(struct mm_struct *mm, pmd_t *pmd,
			   unsigned long addr, unsigned long end)
{
	pte_t *pte;
	spinlock_t *ptl;

	pte = pte_offset_lock(mm, pmd, addr, &ptl);
	do {
		pte_t ptent = *pte;

		pgtable_debug("  addr: %lx, pte: %#lx",
			addr, ptent.pte);

		pte_clear(pte);
	} while (pte++, addr += PAGE_SIZE, addr != end);
	spin_unlock(ptl);
}

static inline void free_pmd_range(struct mm_struct *mm, pud_t *pud,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		free_pte_range(mm, pmd, addr, next);
	} while (pmd++, addr = next, addr != end);
}

static inline void free_pud_range(struct mm_struct *mm, pgd_t *pgd,
				unsigned long addr, unsigned long end,
				unsigned long floor, unsigned long ceiling)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		free_pmd_range(mm, pud, addr, next, floor, ceiling);
	} while (pud++, addr = next, addr != end);
}

/*
 * Clear and free pgtable.
 * Note: this doesn't free the actual pages themselves. That
 * has been handled earlier when unmapping all the memory regions,
 *
 * TODO: This function no longer uses floor and ceiling. Also
 * it never free any pgtable pages, it will only clear the PTE entries.
 * This won't violate logic things, it will only waste some pages.
 * Come back and fix this after deadline!
 */
void free_pgd_range(struct mm_struct *mm,
		    unsigned long __user addr, unsigned long __user end,
		    unsigned long floor, unsigned long ceiling)
{
	pgd_t *pgd;
	unsigned long next, original_addr = addr;

	pgtable_debug("[%#lx - %#lx], floor: %#lx, ceiling: %#lx",
		addr, end, floor, ceiling);

	if (addr > end - 1)
		return;

	pgd = pgd_offset(mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		free_pud_range(mm, pgd, addr, next, floor, ceiling);
	} while (pgd++, addr = next, addr != end);

	flush_tlb_mm_range(mm, original_addr, end);
}

/*
 * TODO: Flush back dirty pages back to memory component!
 */
static unsigned long
zap_pte_range(struct mm_struct *mm, pmd_t *pmd,
	      unsigned long addr, unsigned long end)
{
	spinlock_t *ptl;
	pte_t *start_pte;
	pte_t *pte;

	start_pte = pte_offset_lock(mm, pmd, addr, &ptl);
	pte = start_pte;

	do {
		pte_t ptent = *pte;

		if (pte_none(ptent))
			continue;
		if (pte_present(ptent)) {
			/*
			 * If we remove rmap first, there is a small
			 * time frame where the pcm that pte maps to
			 * does not have corresponding rmap points back.
			 *
			 * If we clear pte first, there is a small
			 * time frame where the rmap that pcm has still 
			 * points back to this pte, but this pte is 0.
			 *
			 * Both create in-consistent view.
			 *
			 * Probably the second one is better, thus we can keep
			 * consistent with move_ptes(). Also, we can catch
			 * this very confidently in rmap code.
			 */
			ptent = ptep_get_and_clear_full(pte);

			/*
			 * TODO:
			 * Deadlock, temporary fix
			 * Other rmap code do: lock pcache, lock pte
			 * But here we do: lock pte, lock pcache.
			 *
			 * To avoid deadlock, release the pte lock (will not
			 * impact correctness, but hurt performance.)
			 */
			spin_unlock(ptl);
			pcache_zap_pte(mm, addr, ptent, pte);
			spin_lock(ptl);
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
 * PTEs are cleared, but not PGD, PUD, and PMD.
 */
void unmap_page_range(struct mm_struct *mm,
		      unsigned long __user addr, unsigned long __user end)
{
	pgd_t *pgd;
	unsigned long next;

	pgtable_debug("[%#lx - %#lx]", addr, end);

	BUG_ON(addr >= end);
	pgd = pgd_offset(mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		next = zap_pud_range(mm, pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
}

/*
 * Release both pgtable pages and the actual pages.
 * Dirty cachelines will be flushed back to memory,
 * and TLB will be flushed at the end.
 *
 * WARNING: Only call this function after memory manager
 * has successfully updated its mmap. Otherwise, it may
 * 1) lower the performance, or 2) cause segfault.
 */
void release_pgtable(struct task_struct *tsk,
		     unsigned long __user start, unsigned long __user end)
{
	struct mm_struct *mm = tsk->mm;

	pgtable_debug("%s[%d] [%#lx - %#lx]",
		tsk->comm, tsk->tgid, start, end);

	/* Free actual pages */
	unmap_page_range(mm, start, end);

	/* Free pgtable pages */
	free_pgd_range(mm, start, end, start, end);
}

/*
 * TODO:
 * Callback to pcache, let pcache update metadata keeping if any.
 */
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

	/* we may not using per-PTE lock */
	if (src_ptl != dst_ptl)
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

	if (src_ptl != dst_ptl)
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

static pmd_t *get_old_pmd(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	if (pgd_none_or_clear_bad(pgd))
		return NULL;

	pud = pud_offset(pgd, addr);
	if (pud_none_or_clear_bad(pud))
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;

	return pmd;
}

static pmd_t *alloc_new_pmd(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	pud = pud_alloc(mm, pgd, addr);
	if (!pud)
		return NULL;

	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
		return NULL;

	return pmd;
}

static void move_ptes(struct mm_struct *mm, pmd_t *old_pmd,
		unsigned long old_addr, unsigned long old_end,
		pmd_t *new_pmd, unsigned long new_addr)
{
	pte_t *old_pte, *new_pte;
	spinlock_t *old_ptl, *new_ptl;
	unsigned long len = old_end - old_addr;

	old_pte = pte_offset_lock(mm, old_pmd, old_addr, &old_ptl);
	new_pte = pte_offset(new_pmd, new_addr);
	new_ptl = pte_lockptr(mm, new_pmd);
	if (new_ptl != old_ptl)
		spin_lock(new_ptl);

	for (; old_addr < old_end; old_pte++, old_addr += PAGE_SIZE,
				   new_pte++, new_addr += PAGE_SIZE) {
		if (pte_none(*old_pte))
			continue;

		/* Let pcache take care of everything */
		if (pcache_move_pte(mm, old_pte, new_pte, old_addr, new_addr))
			WARN_ON_ONCE(1);
	}

	if (new_ptl != old_ptl)
		spin_unlock(new_ptl);
	spin_unlock(old_ptl);

	flush_tlb_mm_range(mm, old_end - len, old_end);
}

#define LATENCY_LIMIT	(64 * PAGE_SIZE)

/*
 * Shift emulated pgtable mapping from
 * 	[old_addr, old_addr + len) ---> [new_addr, new_addr + len)
 * The original mapping for old_addr will be cleared. And the
 * TLB will be flushed at last.
 *
 * RETURN: how much work has been done. Return @len measn fully shifted.
 */
unsigned long move_page_tables(struct task_struct *tsk,
			       unsigned long __user old_addr,
			       unsigned long __user new_addr, unsigned long len)
{
	struct mm_struct *mm = tsk->mm;
	unsigned long extent, next, old_end;
	pmd_t *old_pmd, *new_pmd;

	pgtable_debug("%s[%u] [%#lx - %#lx] -> [%#lx - %#lx]",
		tsk->comm, tsk->tgid, old_addr, old_addr + len,
		new_addr, new_addr + len);

	old_end = old_addr + len;

	for (; old_addr < old_end; old_addr += extent, new_addr += extent) {
		next = (old_addr + PMD_SIZE) & PMD_MASK;
		
		/* even if next overflowed, extent below will be ok */
		extent = next - old_addr;
		if (extent > old_end - old_addr)
			extent = old_end - old_addr;

		old_pmd = get_old_pmd(mm, old_addr);
		if (!old_pmd)
			continue;
		
		new_pmd = alloc_new_pmd(mm, new_addr);
		if (WARN_ON_ONCE(!new_pmd))
			break;
	
		if (WARN_ON_ONCE(!pte_alloc(mm, new_pmd, new_addr)))
			break;

		next = (new_addr + PMD_SIZE) & PMD_MASK;
		if (extent > next - new_addr)
			extent = next - new_addr;
		if (extent > LATENCY_LIMIT)
			extent = LATENCY_LIMIT;

		move_ptes(mm, old_pmd, old_addr, old_addr + extent,
			  new_pmd, new_addr);
	}

	return len + old_addr - old_end;	/* how much done */
}
