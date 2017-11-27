/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROCESSOR_PCACHE_STAT_H_
#define _LEGO_PROCESSOR_PCACHE_STAT_H_

#include <processor/pcache_types.h>

static inline void mod_pset_stat(int i, struct pcache_set *pset,
				 enum pcache_set_stat_item item)
{
	atomic_add(i, &pset->stat[item]);
}

static inline void inc_pset_stat(struct pcache_set *pset,
				 enum pcache_set_stat_item item)
{
	atomic_inc(&pset->stat[item]);
}

static inline void dec_pset_stat(struct pcache_set *pset,
				 enum pcache_set_stat_item item)
{
	atomic_dec(&pset->stat[item]);
}

static inline void inc_pset_fill(struct pcache_set *pset)
{
	inc_pset_stat(pset, NR_PSET_FILL);
}

static inline void dec_pset_fill(struct pcache_set *pset)
{
	dec_pset_stat(pset, NR_PSET_FILL);
}

static inline void inc_pset_eviction(struct pcache_set *pset)
{
	inc_pset_stat(pset, NR_PSET_EVICTIONS);
}

static inline void dec_pset_eviction(struct pcache_set *pset)
{
	dec_pset_stat(pset, NR_PSET_EVICTIONS);
}

#endif /* _LEGO_PROCESSOR_PCACHE_STAT_H_ */
