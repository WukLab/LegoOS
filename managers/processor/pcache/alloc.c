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
#include <lego/jiffies.h>
#include <lego/comp_processor.h>
#include <processor/pcache.h>

/**
 * sysctl_pcache_alloc_timeout_sec
 *
 * The maximum time a pcache_alloc can take due to slowpath eviction.
 */
unsigned long sysctl_pcache_alloc_timeout_sec __read_mostly = 10;

#define WAIT_TABLE_BITS 8
#define WAIT_TABLE_SIZE (1 << WAIT_TABLE_BITS)
static wait_queue_head_t pcache_bit_wait_table[WAIT_TABLE_SIZE] __cacheline_aligned;

void __init pcache_init_waitqueue(void)
{
	int i;

	for (i = 0; i < WAIT_TABLE_SIZE; i++)
		init_waitqueue_head(pcache_bit_wait_table + i);
}

wait_queue_head_t *pcache_bit_waitqueue(void *word, int bit)
{
	const int shift = BITS_PER_LONG == 32 ? 5 : 6;
	unsigned long val = (unsigned long)word << shift | bit;

	return pcache_bit_wait_table + hash_long(val, WAIT_TABLE_BITS);
}

/*
 * In order to wait for pages to become available there must be
 * waitqueues associated with pages. By using a hash table of
 * waitqueues where the bucket discipline is to maintain all
 * waiters on the same queue and wake all when any of the pages
 * become available, and for the woken contexts to check to be
 * sure the appropriate page became available, this saves space
 * at a cost of "thundering herd" phenomena during rare hash
 * collisions.
 */
wait_queue_head_t *pcache_waitqueue(struct pcache_meta *pcm)
{
	return pcache_bit_waitqueue(pcm, 0);
}

/**
 * unlock_pcache - unlock a locked pcache line
 * @pcm: the pcache line
 *
 * The mb is necessary to enforce ordering between the clear_bit and the read
 * of the waitqueue (to avoid SMP races with xxx).
 */
void unlock_pcache(struct pcache_meta *pcm)
{
	BUG_ON(!PcacheLocked(pcm));

	clear_bit(PC_locked, (unsigned long *)&pcm->bits);
	smp_mb();
	__wake_up_bit(pcache_waitqueue(pcm), &pcm->bits, PC_locked);
}

/**
 * __lock_pcache
 * @pcm: the pcache line to lock
 *
 * Get a lock on the pcache line, assuming we need to sleep to get it.
 */
void __lock_pcache(struct pcache_meta *pcm)
{
	DEFINE_WAIT_BIT(wait, &pcm->bits, PC_locked);

	__wait_on_bit_lock(pcache_waitqueue(pcm), &wait, bit_wait,
			TASK_UNINTERRUPTIBLE);
}

static inline struct pcache_meta *
pcache_alloc_fastpath(struct pcache_set *pset)
{
	int way;
	struct pcache_meta *pcm;

	spin_lock(&pset->lock);
	for_each_way_set(pcm, pset, way) {
		if (likely(!TestSetPcacheAllocated(pcm))) {
			spin_unlock(&pset->lock);
			return pcm;
		}
	}
	spin_unlock(&pset->lock);
	return NULL;
}

/*
 * Slowpath: find line to evict and initalize the eviction process,
 * if eviction succeed, try fastpath again. We do have a time limit
 * on this function to avoid livelock.
 */
static struct pcache_meta *
pcache_alloc_slowpath(struct pcache_set *pset, unsigned long address)
{
	struct pcache_meta *pcm;
	int ret;
	unsigned long alloc_start = jiffies;

retry:
	ret = pcache_evict_line(pset, address);
	if (unlikely(ret))
		return NULL;

	/* Do we still have time? */
	if (time_after(jiffies,
		       alloc_start + sysctl_pcache_alloc_timeout_sec * HZ)) {
		WARN(1, "Abort pcache alloc (%ums) pid:%u, addr:%#lx",
			jiffies_to_msecs(jiffies - alloc_start), current->pid, address);
		return NULL;
	}

	pcm = pcache_alloc_fastpath(pset);
	if (unlikely(!pcm))
		goto retry;
	return pcm;
}

/**
 * pcache_alloc
 * @address: user virtual address
 *
 * This function will try to allocate a cacheline from the set
 * that @address belongs to. On success, the returned @pcm has
 * its PcaheAllocated bit set ONLY.
 */
struct pcache_meta *pcache_alloc(unsigned long address)
{
	struct pcache_set *pset;
	struct pcache_meta *pcm;

	pset = user_vaddr_to_pcache_set(address);

	/* Fastpath: try to allocate one directly */
	pcm = pcache_alloc_fastpath(pset);
	if (likely(pcm))
		goto out;

	/* Slowpath: fallback and try to evict one */
	pcm = pcache_alloc_slowpath(pset, address);
	if (likely(pcm))
		goto out;
	return NULL;

out:
	/* May need further initilization in the future */
	return pcm;
}

void pcache_free(struct pcache_meta *p)
{
	BUG_ON(!PcacheAllocated(p) || PcacheValid(p) || PcacheLocked(p));
	ClearPcacheAllocated(p);
}
