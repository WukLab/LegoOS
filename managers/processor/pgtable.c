/*
 * Copyright (c) 2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Only processor manager needs those functions to manipulate the pgtable
 * used to emulate pcache. Those functions work on user pgtable ranges.
 *
 * There major pte functions:
 *	- zap		pcache_zap_pte
 *	- copy		pcache_copy_one_pte
 *	- move		pcache_move_pte
 */

#include <lego/mm.h>
#include <lego/sched.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/memblock.h>
#include <processor/pcache.h>
#include <processor/pgtable.h>
#include <processor/zerofill.h>

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
		pgtable_debug("addr: %lx, pte: %p", addr, pte);

		pte_clear(pte);
	} while (pte++, addr += PAGE_SIZE, addr != end);
	spin_unlock(ptl);
}

static inline void free_pmd_range(struct mm_struct *mm, pud_t *pud,
				unsigned long addr, unsigned long end)
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
				unsigned long addr, unsigned long end)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		free_pmd_range(mm, pud, addr, next);
	} while (pud++, addr = next, addr != end);
}

/*
 * Clear and free user-level pgtable.
 * Note: this doesn't free the actual pages themselves. That
 * has been handled earlier when unmapping all the memory regions,
 *
 * TODO: This function no longer uses floor and ceiling. Also
 * it never free any pgtable pages, it will only clear the PTE entries.
 * This won't violate logic things, it will only waste some pages.
 * Come back and fix this after deadline!
 */
void free_pgd_range(struct mm_struct *mm,
		    unsigned long __user addr, unsigned long __user end)
{
	pgd_t *pgd;
	unsigned long next, original_addr = addr;

	pgtable_debug("[%#lx - %#lx]", addr, end);

	if (addr > end - 1)
		return;

	pgd = pgd_offset(mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		free_pud_range(mm, pgd, addr, next);
	} while (pgd++, addr = next, addr != end);

	flush_tlb_mm_range(mm, original_addr, end);
}

/*
 * TODO:
 * Flush *file-backed* dirty pages!
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
		pte_t ptent;

retry:
		ptent = *pte;
		if (pte_none(ptent))
			continue;
		if (pte_present(ptent)) {
			int ret;

			pgtable_debug("addr: %#lx, pte: %p", addr, pte);
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
			 * Furthermore, this also race with concurrent eviction:
			 * Our old version use pte_get_and_clear() before calling
			 * into pcache_zap_pte(). When concurrent eviction calls
			 * pcache_try_to_unmap(), it will fail to remove the rmap.
			 */
			ret = pcache_zap_pte(mm, addr, ptent, pte, ptl);
			if (likely(!ret))
				continue;
			else if (ret == -EAGAIN) {
				goto retry;
			} else
				WARN_ON_ONCE(1);
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
	free_pgd_range(mm, start, end);
}

/*
 * We enter with both @src_pte and @dst_pte locked.
 * We leave with both @src_pte and @dst_pte locked.
 */
static inline int
pcache_copy_one_pte(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pte_t *dst_pte, pte_t *src_pte, unsigned long addr,
		unsigned long vm_flags, struct task_struct *dst_task)
{
	pte_t pte = *src_pte;
	struct pcache_meta *pcm;

	/*
	 * If it's a COW mapping, write protect it both
	 * in the parent and the child
	 */
	if (is_cow_mapping(vm_flags)) {
		ptep_set_wrprotect(src_pte);
		/*
		 * TODO:
		 * Should be batched
		 * Doing this one by one make fork() very slow.
		 */
		flush_tlb_mm_range(src_mm, addr, addr + PAGE_SIZE);
		pte = pte_wrprotect(pte);
	}

	/*
	 * If it's a shared mapping, mark it clean in
	 * the child:
	 */
	if (vm_flags & VM_SHARED)
		pte = pte_mkclean(pte);

	pte = pte_mkold(pte);
	pte_set(dst_pte, pte);

	/*
	 * Add one more reverse mapping.
	 * Do this after pet_set because rmap will be validated.
	 */
	pcm = pte_to_pcache_meta(pte);
	if (pcm) {
		get_pcache(pcm);

		/*
		 * XXX:
		 * May deadlock. We are holding pte lock. Happens if:
		 * another thread which is doing eviction, already locked
		 * this pcm and tried to acquire pte lock to do unmap.
		 */
		pcache_add_rmap(pcm, dst_pte, addr, dst_mm, dst_task, RMAP_FORK);
	}
	return 0;
}

static inline int
pcache_copy_pte_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		      pmd_t *dst_pmd, pmd_t *src_pmd,
		      unsigned long addr, unsigned long end,
		      unsigned long vm_flags, struct task_struct *dst_task)
{
	pte_t *orig_src_pte, *orig_dst_pte;
	pte_t *src_pte, *dst_pte;
	spinlock_t *src_ptl, *dst_ptl;
	int ret;

	dst_pte = pte_alloc(dst_mm, dst_pmd, addr);
	if (!dst_pte)
		return -ENOMEM;
	dst_ptl = pte_lockptr(dst_mm, dst_pmd);
	spin_lock(dst_ptl);

	src_pte = pte_offset(src_pmd, addr);
	src_ptl = pte_lockptr(src_mm, src_pmd);

	/* Will this have potential deadlock issue? */
	if (src_ptl != dst_ptl)
		spin_lock(src_ptl);

	orig_src_pte = src_pte;
	orig_dst_pte = dst_pte;

	ret = 0;
	do {
		pte_t ptecont = *src_pte;

		if (pte_none(ptecont))
			continue;

		if (!pte_present(ptecont)) {
#ifdef CONFIG_PCACHE_ZEROFILL
			/*
			 * If zerofill is configured, chances are we will
			 * see PTE entries with ZEROFILL bit set. But we
			 * only deal with non-present PTE here. Present ones
			 * need to callback to pcache, which will copy the bit as well.
			 */
			if (unlikely(!pte_zerofill(ptecont))) {
				pr_info("addr: %#lx, ptecont: %#lx\n", addr, ptecont.pte);
				dump_pte(src_pte, "corrupted");
				WARN_ON_ONCE(1);
				continue;
			}

			pte_set(dst_pte, ptecont);
			continue;
#else
			/*
			 * Otherwise, we do not have any extra info
			 * filled within PTE entries. Must be corrupted.
			 */
			dump_pte(src_pte, "corrupted");
			WARN_ON_ONCE(1);
			continue;
#endif
		}

		if (pcache_copy_one_pte(dst_mm, src_mm, dst_pte, src_pte, addr, vm_flags, dst_task)) {
			ret = -ENOMEM;
			break;
		}
	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr != end);

	if (src_ptl != dst_ptl)
		spin_unlock(src_ptl);
	spin_unlock(dst_ptl);

	return 0;
}

static inline int
pcache_copy_pmd_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		      pud_t *dst_pud, pud_t *src_pud,
		      unsigned long addr, unsigned long end,
		      unsigned long vm_flags, struct task_struct *dst_task)
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
		if (pcache_copy_pte_range(dst_mm, src_mm, dst_pmd, src_pmd,
						addr, next, vm_flags, dst_task))
			return -ENOMEM;
	} while (dst_pmd++, src_pmd++, addr = next, addr != end);
	return 0;
}

static inline int
pcache_copy_pud_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		      pgd_t *dst_pgd, pgd_t *src_pgd,
		      unsigned long addr, unsigned long end,
		      unsigned long vm_flags, struct task_struct *dst_task)
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
		if (pcache_copy_pmd_range(dst_mm, src_mm, dst_pud, src_pud,
						addr, next, vm_flags, dst_task))
			return -ENOMEM;
	} while (dst_pud++, src_pud++, addr = next, addr != end);
	return 0;
}

/*
 * Duplicate the pgtable used to emulate pcache.
 * Write-protect both ends if it is COW mapping.
 */
int pcache_copy_page_range(struct mm_struct *dst, struct mm_struct *src,
			   unsigned long addr, unsigned long end,
			   unsigned long vm_flags, struct task_struct *dst_task)
{
	pgd_t *src_pgd, *dst_pgd;
	unsigned long next;
	int ret;

	ret = 0;
	dst_pgd = pgd_offset(dst, addr);
	src_pgd = pgd_offset(src, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(src_pgd))
			continue;
		if (unlikely(pcache_copy_pud_range(dst, src, dst_pgd, src_pgd,
					    addr, next, vm_flags, dst_task))) {
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
		int ret;

retry:
		if (pte_none(*old_pte))
			continue;

		if (!pte_present(*old_pte)) {
#ifdef CONFIG_PCACHE_ZEROFILL
			/*
			 * If zerofill is configured, chances are we will
			 * see PTE entries with ZEROFILL bit set. But we
			 * only deal with non-present PTE here. Present ones
			 * need to callback to pcache, which will move the bit as well.
			 */
			pte_t pte;

			pte = ptep_get_and_clear(old_addr, old_pte);
			if (unlikely(!pte_zerofill(pte))) {
				dump_pte(old_pte, "corrupted");
				WARN_ON_ONCE(1);
				continue;
			}

			pte_set(new_pte, pte);
			continue;
#else
			/*
			 * Otherwise, we do not have any extra info
			 * filled within PTE entries. Must be corrupted.
			 */
			dump_pte(old_pte, "corrupted");
			WARN_ON_ONCE(1);
			continue;
#endif
		}

		ret = pcache_move_pte(mm, old_pte, new_pte, old_addr, new_addr, old_ptl);
		switch (ret) {
		case 0:
			continue;

		/* pte changed after it released lock */
		case -EAGAIN:
			goto retry;

		/* pcache alloc failed */
		case -ENOMEM:
			WARN_ON_ONCE(1);
			goto retry;

		default:
			BUG();
		};
	}

	if (new_ptl != old_ptl)
		spin_unlock(new_ptl);
	spin_unlock(old_ptl);

	flush_tlb_mm_range(mm, old_end - len, old_end);
}

#define LATENCY_LIMIT	(64 * PAGE_SIZE)

/*
 * Shift emulated pgtable mapping from
 *	[old_addr, old_addr + len) ---> [new_addr, new_addr + len)
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

#ifdef CONFIG_PCACHE_ZEROFILL

#ifdef CONFIG_DEBUG_PCACHE_ZEROFILL
#define zerofill_debug(fmt, ...)				\
	pr_debug("%s() cpu%2d " fmt "\n",			\
		__func__, smp_processor_id(), __VA_ARGS__)
#else
static inline void zerofill_debug(const char *fmt, ...) { }
#endif

static inline unsigned long
zerofill_set_pte_range(struct mm_struct *mm, pmd_t *pmd,
		       unsigned long addr, unsigned long end)
{
	spinlock_t *ptl;
	pte_t *ptep;

	ptep = pte_alloc(mm, pmd, addr);
	ptl = pte_lockptr(mm, pmd);

	spin_lock(ptl);
	do {
		ptep_set_zerofill(ptep);

		zerofill_debug(" uvaddr: %#18lx", addr);
	} while (ptep++, addr += PAGE_SIZE, addr != end);
	spin_unlock(ptl);

	return addr;
}

static inline unsigned long
zerofill_set_pmd_range(struct mm_struct *mm, pud_t *pud,
		       unsigned long addr, unsigned long end)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_alloc(mm, pud, addr);
	if (unlikely(!pmd))
		return -ENOMEM;

	do {
		next = pmd_addr_end(addr, end);
		next = zerofill_set_pte_range(mm, pmd, addr, next);
		if (unlikely(next == -ENOMEM))
			return -ENOMEM;
	} while (pmd++, addr = next, addr != end);

	return addr;
}

static inline unsigned long
zerofill_set_pud_range(struct mm_struct *mm, pgd_t *pgd,
		       unsigned long addr, unsigned long end)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_alloc(mm, pgd, addr);
	if (unlikely(!pud))
		return -ENOMEM;

	do {
		next = pud_addr_end(addr, end);
		next = zerofill_set_pmd_range(mm, pud, addr, next);
		if (unlikely(next == -ENOMEM))
			return -ENOMEM;
	} while (pud++, addr = next, addr != end);

	return addr;
}

/*
 * Set the _PAGE_ZEROFILL bit of all PTE entries in range [start, start+len).
 * Page table will be allocated even if the pages will not accessed in the future.
 */
int zerofill_set_range(struct task_struct *p,
		       unsigned long __user start, unsigned long len)
{
	pgd_t *pgd;
	unsigned long end, next;
	struct mm_struct *mm = p->mm;

	end = PAGE_ALIGN(start + len);
	BUG_ON(start >= end);

	zerofill_debug("[%#lx-%#lx] len=%#lx", start, end, len);

	pgd = pgd_offset(mm, start);
	do {
		next = pgd_addr_end(start, end);
		next = zerofill_set_pud_range(mm, pgd, start, next);
		if (unlikely(next == -ENOMEM))
			return -ENOMEM;
	} while (pgd++, start = next, start != end);

	return 0;
}

/*
 * Clear the _PAGE_ZEROFILL bit of all PTE entries in range [start, start+len).
 * Page table is not freed by this function.
 */
int zerofill_clear_range(struct task_struct *p,
			 unsigned long __user start, unsigned long len)
{
	return 0;
}
#endif
