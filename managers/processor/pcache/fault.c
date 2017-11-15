/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/syscalls.h>
#include <lego/comp_processor.h>
#include <asm/io.h>

#include <processor/include/pcache.h>

#ifdef CONFIG_DEBUG_PCACHE
static DEFINE_RATELIMIT_STATE(pcache_debug_rs,
	DEFAULT_RATELIMIT_INTERVAL, DEFAULT_RATELIMIT_BURST);

#define pcache_debug(fmt, ...)						\
({									\
	if (__ratelimit(&pcache_debug_rs))				\
		pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__);	\
})
#else
static inline void pcache_debug(const char *fmt, ...) { }
#endif

static int do_pcache_fill_page(unsigned long address, unsigned long flags,
			       struct pcache_meta *pcm)
{
	int ret, len;
	struct p2m_llc_miss_struct payload;
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

	if (unlikely(len < PCACHE_LINE_SIZE)) {
		if (likely(len == sizeof(int))) {
			int *va_cache = pcache_meta_to_va(pcm);

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

	ret = 0;
out:
	pcache_debug("O pid:%u tgid:%u address:%#lx flags:%#lx pa_cache:%p ret:%d",
		current->pid, current->tgid, address, flags, pa_cache, ret);
	return ret;
}

/*
 * This function handles missing cache lines.
 * We enter with pte unlocked, we return with pte unlocked.
 */
static int pcache_fill_page(struct mm_struct *mm, unsigned long address,
			    pte_t *page_table, pmd_t *pmd, unsigned long flags)
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

	page_table = pte_offset_lock(mm, pmd, address, &ptl);
	if (unlikely(!pte_none(*page_table))) {
		ret = 0;
		goto out;
	}

	/* Fetch page from remote memory */
	ret = do_pcache_fill_page(address, flags, pcm);
	if (ret) {
		ret = VM_FAULT_SIGSEGV;
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
 * We enter wirh pte locked, we return with pte unlocked.
 */
static int pcache_do_wp_page(struct mm_struct *mm, unsigned long address,
			     pte_t *page_table, pmd_t *pmd, spinlock_t *ptl,
			     pte_t orig_pte)
			__releases(ptl)
{
	/*
	 * Use cases
	 * 1) Used for cache flush. Wait until flush finishes
	 * 2) Used to implement COW for fork()
	 */
	panic("TODO");
	return 0;
}

static int pcache_handle_pte_fault(struct mm_struct *mm, unsigned long address,
				   pte_t *pte, pmd_t *pmd, unsigned long flags)
{
	pte_t entry;
	spinlock_t *ptl;

	entry = *pte;
	if (!pte_present(entry))
		return pcache_fill_page(mm, address, pte, pmd, flags);

	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);
	if (unlikely(!pte_same(*pte, entry))) {
		/*
		 * PTE changed before we aquire the lock.
		 * Permission maybe upgraded from RO to RW
		 * by others in the middle (maybe pcache flush routine).
		 */
		goto unlock;
	}
	if (flags & FAULT_FLAG_WRITE) {
		if (!pte_write(entry))
			return pcache_do_wp_page(mm, address, pte, pmd, ptl, entry);
		entry = pte_mkdirty(entry);
	}

	/*
	 * If we are here, it means the PTE is both present and writable.
	 * Then why pgfault happens at all? The case is: two or more CPUs
	 * fault into the same address concurrently. One established the
	 * mapping even before other CPUs do "entry = *pte".
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

	return pcache_handle_pte_fault(mm, address, pte, pmd, flags);
}
