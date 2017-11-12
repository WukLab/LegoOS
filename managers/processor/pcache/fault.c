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
#define pcache_debug(fmt, ...)					\
	printk(KERN_DEBUG "%s() cpu%2d "fmt"\n",		\
		__func__, smp_processor_id(), __VA_ARGS__);
#else
static inline void pcache_debug(const char *fmt, ...) { }
#endif

static DEFINE_SPINLOCK(pcache_alloc_lock);

static struct page *pcache_alloc_cacheline(struct mm_struct *mm, unsigned long address)
{
	void *pa_cache, *va_cache, *va_meta;
	unsigned int way;
	struct page *page;

	spin_lock(&pcache_alloc_lock);
	for_each_way_set(address, pa_cache, va_cache, va_meta, way) {
		if (!pcache_valid(va_meta)) {
			pcache_mkvalid(va_meta);
			break;
		}
	}
	spin_unlock(&pcache_alloc_lock);

	if (unlikely(way == llc_cache_associativity)) {
		WARN(1, "Cache eviction needed!\n");
		return NULL;
	}

	page = virt_to_page(va_cache);
	return page;
}

static void pcache_free_cacheline(struct page *page)
{
	/* TODO */
}

static int do_pcache_fill_page(unsigned long address,
			       unsigned long flags, struct page *page)
{
	int ret, len;
	u64 offset, slice;
	int i, nr_split = CONFIG_PCACHE_FILL_SPLIT_NR;
	struct p2m_llc_miss_struct payload;
	void *pa_cache = (void *)PFN_PHYS(page_to_pfn(page));

	payload.pid = current->pid;
	payload.tgid = current->tgid;
	payload.flags = flags;
	payload.missing_vaddr = address;

	pcache_debug("I pid:%u tgid:%u address:%#lx flags:%#lx pa_cache:%p",
		current->pid, current->tgid, address, flags, pa_cache);

	slice = PAGE_SIZE / nr_split;
	for (i = 0; i < nr_split; i++) {
		offset = i * slice;
		payload.offset = offset;

		len = net_send_reply_timeout(DEF_MEM_HOMENODE, P2M_LLC_MISS,
				&payload, sizeof(payload),
				pa_cache + offset, slice, true,
				DEF_NET_TIMEOUT);

		if (unlikely(len < slice)) {
			if (likely(len == sizeof(int))) {
				int *va_cache = page_to_virt(page);

				/* remote reported error */
				ret = -(*va_cache);
				goto out;
			} else if (len < 0) {
				/* IB is not available */
				ret = -EIO;
				goto out;
			} else {
				WARN(1, "Invalid size: %d\n", len);
				ret = -EFAULT;
				goto out;
			}
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
	struct page *page;
	spinlock_t *ptl;
	pte_t entry;
	int ret;

	page = pcache_alloc_cacheline(mm, address);
	if (!page)
		return VM_FAULT_OOM;

	/* TODO: Need right permission bits */
	entry = mk_pte(page, PAGE_SHARED_EXEC);

	page_table = pte_offset_lock(mm, pmd, address, &ptl);
	if (unlikely(!pte_none(*page_table))) {
		pcache_debug("Concurrent faults: %#lx", address);
		pcache_free_cacheline(page);
		spin_unlock(ptl);
		return 0;
	}

	/* Fetch page from remote memory... */
	ret = do_pcache_fill_page(address, flags, page);
	if (unlikely(ret)) {
		pcache_free_cacheline(page);
		spin_unlock(ptl);
		return VM_FAULT_SIGSEGV;
	}

	pte_set(page_table, entry);
	spin_unlock(ptl);
	return 0;
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
