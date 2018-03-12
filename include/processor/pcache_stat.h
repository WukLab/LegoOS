/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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

	/*
	 * Flush activities
	 * including both pcache and victim cache flush
	 * If victim cache is configured, all flush come from victim
	 */
	PCACHE_CLFLUSH,

	/*
	 * Write-protection fault
	 */
	PCACHE_FAULT_WP,		/* nr of write-protected faults */
	PCACHE_FAULT_WP_COW,		/* nr of copy-on-right faults */
	PCACHE_FAULT_WP_REUSE,		/* nr of reused wp faults */

	PCACHE_FAULT_CONCUR_EVICTION,	/* nr of faults due to concurrent eviction */

	PCACHE_FAULT_FILL_FROM_MEMORY,	/* nr of pcache fill from remote memory */
	PCACHE_FAULT_FILL_FROM_VICTIM,	/* nr of pcache fill from victim cache */

	/*
	 * pcache eviction stat
	 * nr_eviction_failed = triggered - eagain - succeed
	 */
	PCACHE_EVICTION_TRIGGERED,	/* nr of pcache evictions triggered */
	PCACHE_EVICTION_EAGAIN,		/* nr of times eviction tell caller to retry alloc */
	PCACHE_EVICTION_SUCCEED,	/* nr of pcache evictions succeed */

	PCACHE_VICTIM_EVICTION,		/* nr of victim cache eviction happened */

	/*
	 * Victim internal debug counter
	 */
	PCACHE_VICTIM_PREPARE_INSERT,	/* nr of attempt to insert victim */
	PCACHE_VICTIM_FINISH_INSERT,	/* nr of successful insertion into victim */
	PCACHE_VICTIM_FLUSH_SUBMITTED,	/* nr of submitted victim flush jobs */
	PCACHE_VICTIM_FLUSH_FINISHED,	/* nr of finished victim flush jobs */

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

#ifdef CONFIG_COMP_PROCESSOR
void print_pcache_events(void);
#else
static inline void print_pcache_events(void) { }
#endif

#endif /* _LEGO_PROCESSOR_PCACHE_STAT_H_ */
