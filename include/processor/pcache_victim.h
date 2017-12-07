/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Header file for victim cache, within pcache subsystem.
 */

#ifndef _LEGO_PROCESSOR_PCACHE_VICTIM_H_
#define _LEGO_PROCESSOR_PCACHE_VICTIM_H_

#ifdef CONFIG_PCACHE_EVICTION_VICTIM

#define VICTIM_NR_ENTRIES \
	((unsigned int)CONFIG_PCACHE_EVICTION_VICTIM_NR_ENTRIES)

struct pcache_victim_meta {
	unsigned long		flags;
	spinlock_t		lock;		/* protect list operations */

	/*
	 * Natually victim cache line does not map to any
	 * specific pcache lines. The short existence of pcm
	 * is just used to do two-step insertion.
	 *
	 * It will be reset to NULL after insertion finished.
	 */
	struct pcache_meta	*pcm;
	struct list_head	hits;		/* history pid+addr users */
};

struct pcache_victim_hit_entry {
	unsigned long		address;	/* page aligned */
	struct task_struct	*owner;
	struct list_head	next;
};

extern struct pcache_victim_meta *pcache_victim_meta_map;
extern void *pcache_victim_data_map;

#define for_each_victim(victim, index)				\
	for (index = 0, victim = pcache_victim_meta_map;	\
	     index < VICTIM_NR_ENTRIES;				\
	     index++, victim++)

/*
 * victim_meta->flags
 *
 * PCACHE_VICTIM_locked:	victim cache locked. DO NOT TOUCH.
 * PCACHE_VICTIM_allocated:	victim cache allocated.
 * PCACHE_VICTIM_hasdata:	victim cache has real data in its line
 * PCACHE_VICTIM_writeback:	victim cache is being written to memory.
 *
 * Hack: remember to update the victimflag_names array in debug file.
 */
enum pcache_victim_flags {
	PCACHE_VICTIM_locked,
	PCACHE_VICTIM_allocated,
	PCACHE_VICTIM_hasdata,
	PCACHE_VICTIM_writeback,

	NR_PCACHE_VICTIM_FLAGS
};

#define TEST_VICTIM_FLAGS(uname, lname)					\
static inline int Victim##uname(const struct pcache_victim_meta *p)	\
{									\
	return test_bit(PCACHE_VICTIM_##lname, &p->flags);		\
}

#define SET_VICTIM_FLAGS(uname, lname)					\
static inline void SetVictim##uname(struct pcache_victim_meta *p)	\
{									\
	set_bit(PCACHE_VICTIM_##lname, &p->flags);			\
}

#define CLEAR_VICTIM_FLAGS(uname, lname)				\
static inline void ClearVictim##uname(struct pcache_victim_meta *p)	\
{									\
	clear_bit(PCACHE_VICTIM_##lname, &p->flags);			\
}

#define TEST_SET_VICTIM_BITS(uname, lname)				\
static inline int TestSetVictim##uname(struct pcache_victim_meta *p)	\
{									\
	return test_and_set_bit(PCACHE_VICTIM_##lname, &p->flags);	\
}

#define TEST_CLEAR_VICTIM_BITS(uname, lname)				\
static inline int TestClearVictim##uname(struct pcache_victim_meta *p)	\
{									\
	return test_and_clear_bit(PCACHE_VICTIM_##lname, &p->flags);	\
}

#define VICTIM_FLAGS(uname, lname)					\
	TEST_VICTIM_FLAGS(uname, lname)					\
	SET_VICTIM_FLAGS(uname, lname)					\
	CLEAR_VICTIM_FLAGS(uname, lname)				\
	TEST_SET_VICTIM_BITS(uname, lname)				\
	TEST_CLEAR_VICTIM_BITS(uname, lname)

VICTIM_FLAGS(Locked, locked)
VICTIM_FLAGS(Allocated, allocated)
VICTIM_FLAGS(Hasdata, hasdata)
VICTIM_FLAGS(Writeback, writeback)

void __init victim_cache_init(void);
void __init victim_cache_post_init(void);

struct pcache_victim_meta *
victim_prepare_insert(struct pcache_set *pset, struct pcache_meta *pcm);
void victim_finish_insert(struct pcache_victim_meta *victim);

/**
 * pcache_victim_to_kva
 * @victim: victim cache line in question
 *
 * Return victim cache line's kernel virtual address.
 */
static inline void *pcache_victim_to_kva(struct pcache_victim_meta *victim)
{
	unsigned long index = victim - pcache_victim_meta_map;

	BUG_ON(index >= VICTIM_NR_ENTRIES);
	return (void *) (pcache_victim_data_map + index * PCACHE_LINE_SIZE);
}

int victim_submit_flush(struct pcache_victim_meta *victim, bool wait);

static inline int 
victim_submit_flush_nowait(struct pcache_victim_meta *victim)
{
	return victim_submit_flush(victim, false);
}

static inline int
victim_submit_flush_wait(struct pcache_victim_meta *victim)
{
	return victim_submit_flush(victim, true);
}

#endif /* CONFIG_PCACHE_EVICTION_VICTIM */

#endif /* _LEGO_PROCESSOR_PCACHE_VICTIM_H_ */
