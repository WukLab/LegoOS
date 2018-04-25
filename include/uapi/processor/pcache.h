/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_UAPI_PROCESSOR_PCACHE_H_
#define _LEGO_UAPI_PROCESSOR_PCACHE_H_

struct pcache_stat {
	/*
	 * nr_cachelines = nr_cachesets * associativity;
	 * way_stride = nr_cachesets * cacheline_size;
	 */
	unsigned long	nr_cachelines;
	unsigned long	nr_cachesets;
	unsigned long	associativity;
	unsigned long	cacheline_size;
	unsigned long	way_stride;

	/*
	 * Pcache Runtime Stats
	 */
	unsigned long	nr_pgfault;
	unsigned long	nr_pgfault_code;
	unsigned long	nr_flush;
	unsigned long	nr_eviction;
};

#endif /* _LEGO_UAPI_PROCESSOR_PCACHE_H_ */
