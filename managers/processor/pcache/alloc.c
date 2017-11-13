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

/**
 * pcache_find_line_to_evict
 * @pset: the cache set in question
 * @address: the user virtual address maps to @pset
 *
 * Different cache eviction algorithms can be plugged here.
 */
static struct pcache_meta *
pcache_find_line_to_evict(struct pcache_set *pset, unsigned long address)
{
	return NULL;
}

/**
 * pcache_evict_line
 * @pset: the cache set this line belongs to
 * @pcm: the cacheline to evict
 *
 * Given a @pcm, this function will initalize the real eviction process.
 * Only dirty cachelines need to be flushed back to memory component.
 * Return 0 on success, otherwise return negative error values.
 */
static int pcache_evict_line(struct pcache_set *pset, struct pcache_meta *pcm)
{
	return 0;
}

/*
 * Slowpath: find line to evict and initalize the eviction process,
 * if eviction succeed, return the just available line.
 */
static struct pcache_meta *
pcache_alloc_slowpath(struct pcache_set *pset, unsigned long address)
{
	struct pcache_meta *pcm;
	int ret;

	pcm = pcache_find_line_to_evict(pset, address);
	if (unlikely(!pcm))
		return NULL;

	ret = pcache_evict_line(pset, pcm);
	if (unlikely(ret))
		return NULL;

	memset(pcm, 0, sizeof(*pcm));
	__SetPcacheAllocated(pcm);

	return pcm;
}

/**
 * pcache_alloc
 * @address: user virtual address
 *
 * This function will try to allocate a cacheline from the set
 * that @address belongs to. On success, the returned @pcm has
 * its PcaheAllocated bit set. However, it is not valid until
 * data is fetched from remore and mapping is established.
 */
struct pcache_meta *pcache_alloc(unsigned long address)
{
	struct pcache_set *pset;
	struct pcache_meta *pcm;
	int way;

	pset = pcache_addr2set(address);

	spin_lock(&pset->lock);
	for_each_way_set(pcm, way, address) {
		/* Atomically test and set cacheline's allocated bit */
		if (!TestSetPcacheAllocated(pcm)) {
			spin_unlock(&pset->lock);
			goto found;
		}
	}
	spin_unlock(&pset->lock);

	pcm = pcache_alloc_slowpath(pset, address);
	if (unlikely(!pcm))
		return NULL;

found:
	/* May need further initilization in the future */
	return pcm;
}

void pcache_free(struct pcache_meta *p)
{

}
