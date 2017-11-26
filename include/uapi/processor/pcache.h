/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_UAPI_PROCESSOR_H_
#define _LEGO_UAPI_PROCESSOR_H_

struct pcache_stat {
	unsigned long	nr_cachelines;
	unsigned long	nr_cachesets;
	unsigned long	associativity;
	unsigned long	cacheline_size;
	unsigned long	way_stride;
};

#endif /* _LEGO_UAPI_PROCESSOR_H_ */
