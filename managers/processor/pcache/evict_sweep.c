/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Background sweep threads for eviction selection
 */

#include <lego/mm.h>
#include <lego/wait.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/hash.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>
#include <lego/kthread.h>
#include <lego/profile.h>
#include <processor/pcache.h>
#include <processor/processor.h>

static struct task_struct *sweep_thread;

static int
__pcache_evict_sweep_one(struct pcache_meta *pcm,
			 struct pcache_rmap *rmap, void *arg)
{
	return PCACHE_RMAP_AGAIN;
}

static inline void __sweep(void)
{
	int setidx, way;
	struct pcache_set *pset;
	struct pcache_meta *pcm;
	struct rmap_walk_control rwc = {
		.rmap_one = __pcache_evict_sweep_one,
	};

	pcache_for_each_set(pset, setidx) {
		pcache_for_each_way_set(pcm, pset, way) {
			if (!pcache_mapped(pcm))
				continue;
			rmap_walk(pcm, &rwc);
		}
	}
}

static void sweep(void)
{
	u64 start, end;

	start = profile_clock();
	__sweep();
	end = profile_clock();
	pr_info("%s(): %llu ns\n", __func__, end-start);
}

static int kevict_sweepd(void *unused)
{
	for (;;) {
		sweep();
	}
	return 0;
}

int __init evict_sweep_init(void)
{
	sweep_thread = kthread_run(kevict_sweepd, NULL, "kevict_sweepd");
	if (IS_ERR(sweep_thread))
		return PTR_ERR(sweep_thread);
	return 0;
}
