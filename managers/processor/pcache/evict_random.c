/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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

/*
 * XXX
 *
 * This code has not been patched for long and broken.
 * Don't use this.
 */

struct pcache_meta *evict_find_line_random(struct pcache_set *pset)
{
	struct pcache_meta *pcm;
	int way;

	pcache_for_each_way_set(pcm, pset, way) {
		/*
		 * Still under alloc setup, or
		 * freed by someone else before this checking
		 */
		if (!PcacheUsable(pcm)) {
			pcm = ERR_PTR(-EAGAIN);
			goto out;
		}

		/*
		 * Someone else freed after above checking
		 * This is conceptually correct. Worst case:
		 *
		 *  	CPU0			CPU1
		 * t0	PcacheUsable (above)
		 * t1				__put_pcache (free pool)   ref=0
		 * t2	<interrupt>
		 * t3	..			pcache_alloc
		 * t4				    init_pcache_ref_count  ref=1
		 * t5				    <interrupt>
		 * t6	get_pcache_unless_zero      ..			   ref=2
		 * t7				    ..
		 * t8				    ..
		 * t9				    [SetPcacheUsable]
		 * t10				common_do_fill_page()
		 * t11				    rmap ops etc need lock_pcache
		 * t12				    [SetPcacheValid]
		 * t13	trylock_pcache
		 */
		if (!get_pcache_unless_zero(pcm)) {
			pcm = ERR_PTR(-EAGAIN);
			goto out;
		} else {
			/* within timeframe t7-t9 above */
			if (unlikely(!PcacheUsable(pcm)))
				goto put;

			/* within timeframe t10-t12 above */
			if (unlikely(!PcacheValid(pcm)))
				goto put;
		}

		if (!trylock_pcache(pcm))
			goto put;

		if (PcacheWriteback(pcm))
			goto unlock;

		/*
		 * 1 for original allocation
		 * 1 for get_pcache_unless_zero above
		 * Otherwise, it is used by others.
		 *
		 * XXX:
		 * This part need more attention.
		 * Currently we only have pcache_alloc/put, and eviction running.
		 * If later on, we add code such as exit_mmap(), chkpoint_flush(),
		 * those code has to be written with caution, esp. the op sequence
		 * of lock, get/put, flag_set etc.
		 */
		if (unlikely(pcache_ref_count(pcm) > 2))
			goto unlock;

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
		/* Someone else put_pcache() in the middle */
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
