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
#include <lego/sched.h>
#include <processor/pcache_types.h>

/*
 * Per set counters
 */

static inline void mod_pset_event(int i, struct pcache_set *pset,
				  enum pcache_set_stat_item item)
{
	atomic_add(i, &pset->stat[item]);
}

static inline void inc_pset_event(struct pcache_set *pset,
				  enum pcache_set_stat_item item)
{
	atomic_inc(&pset->stat[item]);
}

static inline void dec_pset_event(struct pcache_set *pset,
				 enum pcache_set_stat_item item)
{
	atomic_dec(&pset->stat[item]);
}

/*
 * Lightweight percpu system-wide counters
 *
 * Counters should only be incremented.
 * Counters are handled completely inline.
 */

enum pcache_event_item {
	PCACHE_FAULT,			/* nr of page fault occurred */
	PCACHE_FAULT_WP,		/* nr of write-protected faults */
	PCACHE_FAULT_WP_COW,		/* nr of copy-on-right faults */
	PCACHE_FAULT_CONCUR_EVICTION,	/* nr of faults due to concurrent eviction */
	PCACHE_FAULT_FILL_FROM_MEMORY,	/* nr of pcache fill from remote memory */
	PCACHE_FAULT_FILL_FROM_VICTIM,	/* nr of pcache fill from victim cache */
	PCACHE_EVICTION,		/* nr of evictions happened */
	PCACHE_VICTIM_EVICTION,		/* nr of victim cache eviction happened */

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

#ifdef CONFIG_COMP_PROCESSOR
void sum_pcache_events(struct pcache_event_stat *buf);
void print_pcache_events(void);

static inline void exit_dump_pcache_events(struct task_struct *tsk)
{
	if (unlikely(thread_group_leader(tsk))) {
		print_pcache_events();
	}
}

#else
static inline void print_pcache_events(void) { }
static inline void exit_dump_pcache_events(struct task_struct *tsk) { }
#endif

#endif /* _LEGO_PROCESSOR_PCACHE_STAT_H_ */
