/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/wait.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/hash.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/syscalls.h>
#include <lego/random.h>
#include <lego/jiffies.h>
#include <processor/pcache.h>
#include <processor/processor.h>

#ifdef CONFIG_PCACHE_EVICT_RANDOM
static struct pcache_meta *
pcache_evict_find_line_random(struct pcache_set *pset)
{
	struct pcache_meta *pcm;
	int way;

	spin_lock(&pset->lock);
	for_each_way_set(pcm, pset, way) {
		/*
		 * Must be lines that have these bits set:
		 *	Allocated && Valid
		 * Also it should not be locked or during Writeback
		 */
		if (PcacheAllocated(pcm) && PcacheValid(pcm) &&
		    !PcacheWriteback(pcm)) {
			if (!trylock_pcache(pcm))
				continue;
			else
				break;
		}
	}
	spin_unlock(&pset->lock);

	if (unlikely(way == PCACHE_ASSOCIATIVITY))
		pcm = NULL;
	return pcm;
}
#endif

#ifdef CONFIG_PCACHE_EVICT_FIFO
static struct pcache_meta *
pcache_evict_find_line_fifo(struct pcache_set *pset)
{
	BUG();
}
#endif

#ifdef CONFIG_PCACHE_EVICT_LRU
static struct pcache_meta *
pcache_evict_find_line_lru(struct pcache_set *pset)
{
	BUG();
}
#endif

/**
 * pcache_evict_find_line
 * @pset: the pcache set in question
 *
 * This function will find a line to evict within a set.
 * The returned pcache line MUST be locked.
 */
static inline struct pcache_meta *
pcache_evict_find_line(struct pcache_set *pset)
{
#ifdef CONFIG_PCACHE_EVICT_RANDOM
	return pcache_evict_find_line_random(pset);
#elif defined(CONFIG_PCACHE_EVICT_FIFO)
	return pcache_evict_find_line_fifo(pset);
#elif defined(CONFIG_PCACHE_EVICT_LRU)
	return pcache_evict_find_line_lru(pset);
#endif
}

/*
 * @pcm must be locked when called.
 * Only dirty cachelines need to be flushed back to memory component.
 * Return 0 on success, otherwise return negative error values.
 *
 * Note while developing:
 * 1) need to invalidate pte and flush dirty page back to memory
 * 2) If we invalidate pte first, other threads may try to read/write at the same time,
 *    which means a pgfault will happen right after invalidation. The other thread will
 *    find its pte empty, and try to allocate a new cacheline and then fetch from remote.
 *    Meanwhile, this function may still has NOT finished flushing back the dirty page.
 *    Then this is not doable.
 * 3) If we flush first, and do not change the PTE. Then other thread may write to this page
 *    concurrently, then the page flushed back is broken.
 *    What if we a) make pte read-only, b) flush, c) invalidate?
 *    Then if a thread write to the page while we are in the middle of b) flush, then that thread
 *    will have a page fault. It will be able to find the pte, and corresponding pa/pcm. Then
 *    it can do lock_pcache(), it will be put to sleep. We wake them (may have N threads) after
 *    we finish c) invalidate.
 *    Sounds doable.
 *
 * 4) 12/01/17
 *    Things keep moving, we decided to have victim cache.
 *    But the rule of "don't copy broken page" still applys.
 */
static int do_pcache_evict_line(struct pcache_set *pset, struct pcache_meta *pcm)
{
	int ret = 0;

#ifndef CONFIG_PCACHE_VICTIM
	/* 1) write-protect from all threads */
	pcache_wrprotect(pcm);

	/* 2) Safely flush back */
	pcache_flush_one(pcm);

	/* 3) unmap all PTEs */
	pcache_try_to_unmap(pcm);
#else
	/* 1) add entries to per set list */
	pset_add_eviction(pset, pcm);

	/* 2) Remove unmap, but don't free rmap */
	pcache_try_to_unmap_reserve(pcm);
	pcache_flush_one(pcm);
	pcache_free_reserved_rmap(pcm);

	/* 3) remove entries */
	pset_remove_eviction(pset, pcm);
#endif

	ClearPcacheValid(pcm);
	unlock_pcache(pcm);
	pcache_free(pcm);

	return ret;
}

/**
 * pcache_evict_line
 * @pset: the pcache set to find a line to evict
 * @address: the user virtual address who initalized this eviction
 *
 * This function will try to evict one cache line from @pset.
 * If succeed, the cache line will be flushed back to its backing memory.
 * This function can be called concurrently: the selection of cache line
 * is serialized by pset lock, the real eviction procedure can be overlapped.
 *
 * Return 0 on success, otherwise on failures.
 */
int pcache_evict_line(struct pcache_set *pset, unsigned long address)
{
	struct pcache_meta *pcm;
	int ret;

	inc_pset_eviction(pset);
	inc_pcache_event(PCACHE_EVICTION);

	pcm = pcache_evict_find_line(pset);
	if (!pcm)
		return -ENOMEM;

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);
	ret = do_pcache_evict_line(pset, pcm);
	if (ret)
		return -ENOMEM;
	return 0;
}
