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

#include <lego/percpu.h>
#include <processor/pcache_types.h>

/*
 * Per set counters
 */

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
	inc_pset_stat(pset, PSET_FILL);
}

static inline void inc_pset_eviction(struct pcache_set *pset)
{
	inc_pset_stat(pset, PSET_EVICTIONS);
}

/*
 * Lightweight percpu system-wide counters
 *
 * Counters should only be incremented.
 * Counters are handled completely inline.
 */

enum pcache_event_item {
	PCACHE_FAULT,		/* nr of page fault occurred */
	PCACHE_FAULT_WP,	/* nr of write-protected faults */
	PCACHE_FAULT_WP_COW,	/* nr of copy-on-right faults */
	PCACHE_FAULT_EVICTION,	/* nr of faults due to concurrent eviction */
	PCACHE_FAULT_FILL,	/* nr of cache fill from memory */
	PCACHE_EVICTION,	/* nr of evictions */

	NR_PCACHE_EVENT_ITEMS,
};

struct pcache_event_stat {
	unsigned long event[NR_PCACHE_EVENT_ITEMS];
};

DECLARE_PER_CPU(struct pcache_event_stat, pcache_event_stats);

static inline void inc_pcache_event(enum pcache_event_item item)
{
	this_cpu_inc(pcache_event_stats.event[item]);
}

static inline void __inc_pcache_event(enum pcache_event_item item)
{
	__this_cpu_inc(pcache_event_stats.event[item]);
}

void sum_pcache_events(struct pcache_event_stat *buf);
void print_pcache_events(void);

#endif /* _LEGO_PROCESSOR_PCACHE_STAT_H_ */
