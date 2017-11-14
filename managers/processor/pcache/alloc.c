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
#include <lego/jiffies.h>
#include <lego/comp_processor.h>
#include <asm/io.h>

#include <processor/include/pcache.h>

/* Pcache is locked upon return */
static struct pcache_meta *
pcache_evict_find_line(struct pcache_set *pset, unsigned long address)
{
	struct pcache_meta *pcm;
	int way;

	spin_lock(&pset->lock);
	for_each_way_set(pcm, way, address) {
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

/*
 * @pcm is locked by caller.
 * Only dirty cachelines need to be flushed back to memory component.
 * Return 0 on success, otherwise return negative error values.
 */
static int __pcache_evict_line(struct pcache_set *pset, struct pcache_meta *pcm)
{
	return 0;
}

/* Return 0 if a line has been evicted, otherwise -1 */
static int pcache_evict_line(struct pcache_set *pset, unsigned long address)
{
	struct pcache_meta *pcm;
	int ret;

	pcm = pcache_evict_find_line(pset, address);
	if (unlikely(!pcm))
		return -1;

	ret = __pcache_evict_line(pset, pcm);
	if (unlikely(ret))
		return -1;
	return 0;
}

static inline struct pcache_meta *
__pcache_alloc_from_set(struct pcache_set *pset, unsigned long address)
{
	int way;
	struct pcache_meta *pcm;

	spin_lock(&pset->lock);
	for_each_way_set(pcm, way, address) {
		if (!TestSetPcacheAllocated(pcm)) {
			spin_unlock(&pset->lock);
			return pcm;
		}
	}
	spin_unlock(&pset->lock);
	return NULL;
}

/* By default, abort pcache allocation after 5 seconds */
unsigned long sysctl_pcache_alloc_timeout __read_mostly = 5 * HZ;

/*
 * Slowpath: find line to evict and initalize the eviction process,
 * if eviction succeed, return the just available line.
 */
static struct pcache_meta *
__pcache_alloc_slowpath(struct pcache_set *pset, unsigned long address)
{
	struct pcache_meta *pcm;
	int ret;
	unsigned long alloc_start = jiffies;

retry:
	ret = pcache_evict_line(pset, address);
	if (unlikely(ret))
		return NULL;

	if (time_after(jiffies, alloc_start + sysctl_pcache_alloc_timeout)) {
		pr_warn("Abort pcache alloc (%ums) from pid:%u, addr: %#lx\n",
			jiffies_to_msecs(jiffies - alloc_start), current->pid, address);
		return NULL;
	}

	pcm = __pcache_alloc_from_set(pset, address);
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

	pset = pcache_addr_to_pcache_set(address);
	pcm = __pcache_alloc_from_set(pset, address);
	if (likely(pcm))
		goto out;

	pcm = __pcache_alloc_slowpath(pset, address);
	if (likely(pcm))
		goto out;
	return NULL;

out:
	/* May need further initilization in the future */
	return pcm;
}

void pcache_free(struct pcache_meta *p)
{
	BUG_ON(!PcacheAllocated(p));
}
