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
#include <lego/kernel.h>
#include <lego/random.h>
#include <lego/jiffies.h>
#include <processor/pcache.h>
#include <processor/processor.h>

struct pcache_meta *evict_find_line_random(struct pcache_set *pset)
{
	struct pcache_meta *pcm;
	int way;

	pcache_for_each_way_set(pcm, pset, way) {
		/*
		 * Must be lines that have these bits set:
		 *	Usable && Valid
		 * Also it should not be locked or during Writeback
		 */
		if (PcacheUsable(pcm) && PcacheValid(pcm) &&
		    !PcacheWriteback(pcm)) {
			if (!trylock_pcache(pcm))
				continue;
			else
				break;
		}
	}

	if (unlikely(way == PCACHE_ASSOCIATIVITY))
		pcm = NULL;
	return pcm;
}
