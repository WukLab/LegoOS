/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROCESSOR_PCACHE_SWEEP_H_
#define _LEGO_PROCESSOR_PCACHE_SWEEP_H_

#include <processor/pcache_types.h>

/*
 * Common sweep threads for certain eviction algorithms:
 * 	LRU: Least-Recently Used
 */
#ifdef CONFIG_PCACHE_EVICT_COMMON_SWEEP
int __init evict_sweep_init(void);
#else
static inline int evict_sweep_init(void) { return 0; }
#endif

#endif /* _LEGO_PROCESSOR_PCACHE_SWEEP_H_ */
