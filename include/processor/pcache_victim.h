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

#define VICTIM_NR_ENTRIES \
	((unsigned int)CONFIG_PCACHE_EVICTION_VICTIM_NR_ENTRIES)

struct pcache_victim_meta {
	unsigned long		flags;
	unsigned long		address;	/* page aligned user va */
	pid_t			pid;		/* thread_group id */
	struct pcache_meta	*pcm;		/* associated pcm */
};

/*
 * victim_meta->flags
 *
 * PCACHE_VICTIM_locked:	victim cache locked. DO NOT TOUCH.
 * PCACHE_VICTIM_allocated:	victim cache allocated.
 * PCACHE_VICTIM_writeback:	victim cache is being written to memory.
 *
 * Hack: remember to update the victimflag_names array in debug file.
 */
enum pcache_victim_flags {
	PCACHE_VICTIM_locked,
	PCACHE_VICTIM_allocated,
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
VICTIM_FLAGS(Writeback, writeback)

void __init pcache_init_victim_cache(void);
void victim_prepare_insert(struct pcache_set *, struct pcache_meta *);
void victim_finish_insert(struct pcache_meta *);

#endif /* _LEGO_PROCESSOR_PCACHE_VICTIM_H_ */
