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
		/* Someone else freed before this checking */
		if (!PcacheUsable(pcm)) {
			pcm = ERR_PTR(-EAGAIN);
			goto out;
		}

		/* Someone else freed after above checking */
		if (!get_pcache_unless_zero(pcm)) {
			pcm = ERR_PTR(-EAGAIN);
			goto out;
		}

		if (!trylock_pcache(pcm))
			goto put;

		if (PcacheWriteback(pcm))
			goto unlock;

		/*
		 * 1 for original allocation
		 * 1 for get_pcache_unless_zero above
		 * Otherwise, it is used by others.
		 */
		if (unlikely(pcache_ref_count(pcm) > 2))
			goto unlock;
		else
			goto got_one;

got_one:
		/*
		 * Now, we have a candidate that is:
		 * 1) locked by us
		 * 2) not under writeback
		 * 3) not used by others
		 */
		SetPcacheReclaim(pcm);
		goto out;

unlock:
		unlock_pcache(pcm);
put:
		/* Someone else freed in the middle */
		if (put_pcache_testzero(pcm)) {
			__put_pcache(pcm);
			pcm = ERR_PTR(-EAGAIN);
			goto out;
		}
	}

	/* Failed to find one??? */
	if (unlikely(way == PCACHE_ASSOCIATIVITY))
		pcm = NULL;
out:
	return pcm;
}
