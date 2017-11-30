/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Locking ordering:
 * 	pcache_lock	(may sleep)
 * 	pte_lock
 *
 * Rmap operations will lock in this order. Pgfault code below
 * will probably acquire pte_lock first, then it must NOT call
 * lock_pcache() anymore, which may sleep. The only safe way here
 * is to call trylock_pcache() after pte_lock is acquired.
 */

#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/syscalls.h>
#include <lego/ratelimit.h>
#include <asm/io.h>

#include <processor/pcache.h>
#include <processor/processor.h>

#ifdef CONFIG_DEBUG_PCACHE_FILL
#ifdef CONFIG_DEBUG_PCACHE_FILL_UNLIMITED
#define pcache_debug(fmt, ...)						\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__);
#else
/* 4 msg/sec at most? */
static DEFINE_RATELIMIT_STATE(pcache_debug_rs, 1, 4);

#define pcache_debug(fmt, ...)						\
({									\
	if (__ratelimit(&pcache_debug_rs))				\
		pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__);	\
})
#endif
#else
static inline void pcache_debug(const char *fmt, ...) { }
#endif

static void print_bad_pte(struct mm_struct *mm, unsigned long addr, pte_t pte,
			  struct pcache_meta *pcm)
{
	pgd_t *pgd = pgd_offset(mm, addr);
	pud_t *pud = pud_offset(pgd, addr);
	pmd_t *pmd = pmd_offset(pud, addr);

	pr_err("BUG: Bad page map in process %s pte:%08llx pmd:%08llx\n",
		current->comm, (long long)pte_val(pte), (long long)pmd_val(*pmd));

	if (pcm)
		dump_pcache_meta(pcm, "bad pte");
	dump_stack();
}

static int
__pcache_do_fill_page(unsigned long address, unsigned long flags,
		      struct pcache_meta *pcm)
{
	int ret, len;
	struct p2m_llc_miss_struct payload;
	struct pcache_set *pset;
	void *pa_cache = pcache_meta_to_pa(pcm);

	payload.pid = current->pid;
	payload.tgid = current->tgid;
	payload.flags = flags;
	payload.missing_vaddr = address;

	pcache_debug("I pid:%u tgid:%u address:%#lx flags:%#lx pa_cache:%p",
		current->pid, current->tgid, address, flags, pa_cache);

	len = net_send_reply_timeout(DEF_MEM_HOMENODE, P2M_LLC_MISS,
			&payload, sizeof(payload),
			pa_cache, PCACHE_LINE_SIZE, true, DEF_NET_TIMEOUT);

	if (unlikely(len < (int)PCACHE_LINE_SIZE)) {
		if (likely(len == sizeof(int))) {
			int *va_cache = pcache_meta_to_kva(pcm);

			/* remote reported error */
			ret = -(*va_cache);
			goto out;
		} else if (len < 0) {
			/*
			 * Network error:
			 * EIO: IB is not available
			 * ETIMEDOUT: timeout for reply
			 */
			ret = len;
			goto out;
		} else {
			WARN(1, "Invalid size: %d\n", len);
			ret = -EFAULT;
			goto out;
		}
	}

	/* Update counting */
	pset = pcache_meta_to_pcache_set(pcm);
	inc_pset_fill(pset);
	inc_pcache_event(PCACHE_FILL);

	ret = 0;
out:
	pcache_debug("O pid:%u tgid:%u address:%#lx flags:%#lx pa_cache:%p ret:%d",
		current->pid, current->tgid, address, flags, pa_cache, ret);
	return ret;
}

/*
 * This function handles normal cache line misses.
 * We enter with pte unlocked, we return with pte unlocked.
 */
static int pcache_do_fill_page(struct mm_struct *mm, unsigned long address,
			       pte_t *page_table, pmd_t *pmd,
			       unsigned long flags)
{
	struct pcache_meta *pcm;
	spinlock_t *ptl;
	pte_t entry;
	int ret;

	pcm = pcache_alloc(address);
	if (!pcm)
		return VM_FAULT_OOM;

	/* TODO: Need right permission bits */
	entry = pcache_meta_mk_pte(pcm, PAGE_SHARED_EXEC);

	/* Concurrent faults are serialized by this lock */
	page_table = pte_offset_lock(mm, pmd, address, &ptl);
	if (unlikely(!pte_none(*page_table))) {
		ret = 0;
		goto out;
	}

	ret = __pcache_do_fill_page(address, flags, pcm);
	if (ret) {
		ret = VM_FAULT_SIGSEGV;
		goto out;
	}

	ret = pcache_add_rmap(pcm, page_table, address);
	if (ret) {
		ret = VM_FAULT_OOM;
		goto out;
	}

	SetPcacheValid(pcm);

	pte_set(page_table, entry);
	spin_unlock(ptl);

	return 0;

out:
	pcache_free(pcm);
	spin_unlock(ptl);
	return ret;
}

/*
 * This function handles present write-protected cache lines.
 *
 * We enter wirh pte *locked*, we return with pte *unlocked*.
 */
static int pcache_do_wp_page(struct mm_struct *mm, unsigned long address,
			     pte_t *page_table, pmd_t *pmd, spinlock_t *ptl,
			     pte_t orig_pte) __releases(ptl)
{
	struct pcache_meta *pcm;
	int ret;

	pcm = pte_to_pcache_meta(orig_pte);
	if (!pcm) {
		print_bad_pte(mm, address, orig_pte, NULL);
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	/*
	 * Pcache line might be locked by eviction routine.
	 * But we must NOT sleep here because we are holding pte lock.
	 * Just return to release the pte lock, so others can proceeed
	 * and finish what they are doing.
	 */
	if (likely(!trylock_pcache(pcm))) {
		ret = 0;
		inc_pcache_event(PCACHE_WP_EVICTION);
		goto out;
	}

	panic("COW is not implemented now!");
	unlock_pcache(pcm);
	inc_pcache_event(PCACHE_WP_COW);

	ret = 0;
out:
	spin_unlock(ptl);
	inc_pcache_event(PCACHE_WP);
	return ret;
}

static int pcache_handle_pte_fault(struct mm_struct *mm, unsigned long address,
				   pte_t *pte, pmd_t *pmd, unsigned long flags)
{
	pte_t entry;
	spinlock_t *ptl;

	entry = *pte;
	if (likely(!pte_present(entry))) {
		if (likely(pte_none(entry)))
			return pcache_do_fill_page(mm, address, pte, pmd, flags);

		/* Lego does not fill any extra info into PTE */
		print_bad_pte(mm, address, entry, NULL);
		BUG();
	}

	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);
	if (unlikely(!pte_same(*pte, entry)))
		goto unlock;

	if (flags & FAULT_FLAG_WRITE) {
		if (likely(!pte_write(entry)))
			return pcache_do_wp_page(mm, address, pte, pmd, ptl, entry);
		entry = pte_mkdirty(entry);
	}

	/*
	 * If we are here, it means the PTE is both present and writable.
	 * Then why pgfault happens at all? The case is: two or more CPUs
	 * fault into the same address concurrently. One established the
	 * mapping even before other CPUs do "entry = *pte" in first line.
	 */
	entry = pte_mkyoung(entry);
	if (!pte_same(*pte, entry) && (flags & FAULT_FLAG_WRITE))
		*pte = entry;

unlock:
	spin_unlock(ptl);
	return 0;
}

/**
 * pcache_handle_fault		-	Emulate DRAM cache miss
 * @mm: address space in question
 * @address: the missing virtual address
 * @flags: how the page fault happens
 *
 * This function emulate a DRAM cache miss. This function will
 * look up the mapping, send LLC miss request to corresponding
 * memory component, and establish the pgtable mapping at last.
 * This function is synchronous, and will involve network.
 *
 * Return 0 on success, otherwise return VM_FAULT_XXX flags.
 */
int pcache_handle_fault(struct mm_struct *mm,
			unsigned long address, unsigned long flags)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, address);
	pud = pud_alloc(mm, pgd, address);
	if (!pud)
		return VM_FAULT_OOM;
	pmd = pmd_alloc(mm, pud, address);
	if (!pmd)
		return VM_FAULT_OOM;
	pte = pte_alloc(mm, pmd, address);
	if (!pte)
		return VM_FAULT_OOM;

	inc_pcache_event(PCACHE_FAULT);
	return pcache_handle_pte_fault(mm, address, pte, pmd, flags);
}
