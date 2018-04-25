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
#include <lego/log2.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/syscalls.h>
#include <lego/memblock.h>

#include <processor/pcache.h>
#include <processor/processor.h>

SYSCALL_DEFINE1(pcache_stat, struct pcache_stat __user *, statbuf)
{
	struct pcache_stat kstat;

	/* General info */
	kstat.nr_cachelines = nr_cachelines;
	kstat.nr_cachesets = nr_cachesets;
	kstat.associativity = PCACHE_ASSOCIATIVITY;
	kstat.cacheline_size = PCACHE_LINE_SIZE;
	kstat.way_stride = pcache_way_cache_stride;

	/* Runtime stats */
	kstat.nr_pgfault = pcache_event(PCACHE_FAULT);
	kstat.nr_pgfault_code = pcache_event(PCACHE_FAULT_CODE);
	kstat.nr_flush = pcache_event(PCACHE_CLFLUSH);
	kstat.nr_eviction = pcache_event(PCACHE_EVICTION_SUCCEED);

	if (copy_to_user(statbuf, &kstat, sizeof(kstat)))
		return -EFAULT;
	return 0;
}
