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
 * pcache set counters
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

	PCACHE_FAULT_FILL_ZEROFILL,	/* nr of zero fill + async net */
	PCACHE_FAULT_FILL_FROM_MEMORY,	/* nr of pcache fill from remote memory */
	PCACHE_FAULT_FILL_FROM_VICTIM,	/* nr of pcache fill from victim cache */

	/*
	 * pcache eviction stat
	 * triggered: how many times pcache_alloc wants evict lines
	 * eagain_freeable: someone freed before eviction starting find a condidate
	 * egain_concurrent: the condidate who has been unmapped has concurrent users
	 * failure_find: algorithm part failed to find a candidate
	 * failure_evict: mechanism part failed to evict the candidate
	 * succeed: evicted a line
	 */
	PCACHE_EVICTION_TRIGGERED,
	PCACHE_EVICTION_EAGAIN_FREEABLE,
	PCACHE_EVICTION_EAGAIN_CONCURRENT,
	PCACHE_EVICTION_FAILURE_FIND,
	PCACHE_EVICTION_FAILURE_EVICT,
	PCACHE_EVICTION_SUCCEED,

	/*
	 * triggered = eagain + succeed
	 * Failure is not an option for victim cache eviction 
	 */
	PCACHE_VICTIM_EVICTION_TRIGGERED,	/* nr of victim cache eviction triggered */
	PCACHE_VICTIM_EVICTION_EAGAIN,		/* nr of times eviction tell caller to retry */
	PCACHE_VICTIM_EVICTION_SUCCEED,		/* nr of successful victim cache evictions */

	/*
	 * Victim internal debug counter
	 */
	PCACHE_VICTIM_PREPARE_INSERT,	/* nr of attempt to insert victim */
	PCACHE_VICTIM_FINISH_INSERT,	/* nr of successful insertion into victim */
	PCACHE_VICTIM_FLUSH_SUBMITTED,	/* nr of submitted victim flush jobs */
	PCACHE_VICTIM_FLUSH_FINISHED,	/* nr of finished victim flush jobs */
	PCACHE_VICTIM_FLUSH_ASYNC_RUN,	/* nr of times async victim_flushd got running */
	PCACHE_VICTIM_FLUSH_SYNC,	/* nr of times sync flush is invoked */

	PCACHE_SWEEP_RUN,		/* nr of whole pcache sweep runned */
	PCACHE_SWEEP_NR_PSET,		/* nr of pset that have been sweeped */
	PCACHE_SWEEP_NR_MOVED_PCM,	/* nr of moved pcache lines */

	PCACHE_MREMAP_PSET_SAME,
	PCACHE_MREMAP_PSET_DIFF,

	NR_PCACHE_EVENT_ITEMS,
};

struct pcache_event_stat {
	atomic_long_t event[NR_PCACHE_EVENT_ITEMS];
};

extern struct pcache_event_stat pcache_event_stats;

static inline void inc_pcache_event(enum pcache_event_item item)
{
	atomic_long_inc(&pcache_event_stats.event[item]);
}

#ifdef CONFIG_COMP_PROCESSOR
void print_pcache_events(void);
#else
static inline void print_pcache_events(void) { }
#endif

#endif /* _LEGO_PROCESSOR_PCACHE_STAT_H_ */
