/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROCESSOR_PCACHE_TYPES_H_
#define _LEGO_PROCESSOR_PCACHE_TYPES_H_

#include <lego/const.h>
#include <lego/bitops.h>
#include <lego/spinlock.h>

struct pcache_meta;

#define PCACHE_LINE_SIZE_SHIFT		(CONFIG_PCACHE_LINE_SIZE_SHIFT)
#define PCACHE_ASSOCIATIVITY_SHIFT	(CONFIG_PCACHE_ASSOCIATIVITY_SHIFT)

#define PCACHE_LINE_SIZE		(_AC(1,UL) << PCACHE_LINE_SIZE_SHIFT)
#define PCACHE_LINE_MASK		(~(PCACHE_LINE_SIZE-1))
#define PCACHE_ASSOCIATIVITY		(_AC(1,UL) << PCACHE_ASSOCIATIVITY_SHIFT)
#define PCACHE_META_SIZE		(sizeof(struct pcache_meta))

#define PCACHE_LINE_NR_PAGES		(PCACHE_LINE_SIZE / PAGE_SIZE)

enum pcache_set_stat_item {
	PSET_FILL_MEMORY,
	PSET_FILL_VICTIM,
	PSET_EVICTION,

	NR_PSET_STAT_ITEMS
};

#ifdef CONFIG_PCACHE_EVICTION_PERSET_LIST
struct pset_eviction_entry {
	unsigned long		address;	/* page aligned */
	struct task_struct	*owner;
	struct pcache_meta	*pcm;		/* associated pcm */
	struct list_head	next;
};
#endif

/**
 * struct pcache_set	- Metadata for each cache set
 * @lock: protect (de-)allocation of all ways within this set
 *        protect rmap operations against all ways within this set
 *
 * FAT NOTE:
 * If you add anything here, do not forget to check if this
 * new field needs to be initialized in init_pcache_set_map().
 */
struct pcache_set {
	atomic_t		stat[NR_PSET_STAT_ITEMS];

	/*
	 * Eviction Algorithms Specific
	 */

#ifdef CONFIG_PCACHE_EVICT_LRU
	spinlock_t		lru_lock;
	struct list_head	lru_list;
	atomic_t		nr_lru;
#endif

	/*
	 * Eviction Mechanism Specific
	 */

#ifdef CONFIG_PCACHE_EVICTION_VICTIM
	/*
	 * Number of pcache lines in this set that are currently
	 * living in the victim cache. Updated by victim code.
	 *
	 * Used by pgfault to have a quick check.
	 */
	atomic_t		nr_victims;

#elif defined (CONFIG_PCACHE_EVICTION_PERSET_LIST)
	struct list_head	eviction_list;
	spinlock_t		eviction_list_lock;
#endif
} ____cacheline_aligned;

/**
 * struct pcache_meta	- Metadata about one pcache line
 * @bits: various state bits (see below)
 * @rmap: reverse mapping info
 * @mapcount: count of ptes mapped to this pcm
 *
 * You can think this structure as the traditional metadata
 * part for a cache line, but with some addtional fields. And
 * this structure is *CPU cacheline size* aligned to minimize
 * CPU cacheline pingpong between different cores.
 *
 * FAT NOTE:
 * If you add anything here, do not forget to check if this
 * new field needs to be initialized in init_pcache_meta_map().
 */
struct pcache_meta {
	unsigned long		bits;
	struct list_head	rmap;
	atomic_t		mapcount;
	atomic_t		_refcount;

#ifdef CONFIG_PCACHE_EVICT_LRU
	struct list_head	lru;
#endif
} ____cacheline_aligned;

enum pcache_rmap_flags {
	PCACHE_RMAP_reserved,

	NR_PCACHE_RMAP_FLAGS
};

struct pcache_rmap {
	pte_t			*page_table;
	unsigned long		flags;
	struct task_struct	*owner;

	/*
	 * Hack:
	 * This is NOT page aligned.
	 * AND PAGE_MASK if needed by others.
	 */
	unsigned long		address;
	struct list_head	next;
};

#define TEST_RMAP_FLAGS(uname, lname)				\
static inline int Rmap##uname(const struct pcache_rmap *p)	\
{								\
	return test_bit(PCACHE_RMAP_##lname, &p->flags);	\
}

#define SET_RMAP_FLAGS(uname, lname)				\
static inline void SetRmap##uname(struct pcache_rmap *p)	\
{								\
	set_bit(PCACHE_RMAP_##lname, &p->flags);		\
}

#define CLEAR_RMAP_FLAGS(uname, lname)				\
static inline void ClearRmap##uname(struct pcache_rmap *p)	\
{								\
	clear_bit(PCACHE_RMAP_##lname, &p->flags);		\
}

#define RMAP_FLAGS(uname, lname)				\
	TEST_RMAP_FLAGS(uname, lname)				\
	SET_RMAP_FLAGS(uname, lname)				\
	CLEAR_RMAP_FLAGS(uname, lname)

RMAP_FLAGS(Reserved, reserved)

/*
 * pcacheline->bits
 *
 * PC_locked:		Pcacheline is locked. DO NOT TOUCH.
 * PC_allocated:	Pcacheline is allocated, but may not be usable (internal)
 * PC_usable:		Pcacheline is usable, for all users (public)
 * PC_valid:		Pcacheline has a valid mapping and content.
 * PC_dirty:		Pcacheline is dirty
 * PC_reclaim:		Pcacheline was selected to be evicted
 * PC_writeback:	Pcacheline is being writtern back to memory
 *
 * Hack: remember to update the pcacheflag_names array in debug file.
 *
 * Note:
 * 1) pcache allocator use the PC_allocated bit to guard allocation.
 * Once a cache line is selected, the PC_allocated bit is set. However,
 * allocator still needs to perform some initial setup before return to
 * caller. PC_uable is set once all setuo is done, and it means this
 * cache line can be used safely by all code.
 *
 * 2) PC_valid is more like the traditional cache valid bit. It is set when
 * the pcache line has established a valid mapping to user pgtable.
 * 
 * 3) In a pcache's life time, the transition of different states is:
 *
 *        Locked  Allocated  Usable  Valid  Dirty  Writeback
 * Free:
 *        0       0          0       0      0      0
 * Alloc:
 *        0       1          0       0      0      0	(pcache_alloc_fastpath())
 *        0       1          1       0      0      0	( ..set_pcache_usable())
 *        0       1          1       1      0      0	(common_do_fill_page() after pte_set)
 *
 *        0       0          0       0      0      0
 *
 * 4) In theory, eviction algorithm should pick lines with
 * 	Allocated & Usable & Valid bits set.
 */
enum pcache_meta_bits {
	PC_locked,
	PC_allocated,
	PC_usable,
	PC_valid,
	PC_dirty,
	PC_reclaim,
	PC_writeback,

	__NR_PCLBITS,
};

#define TEST_PC_BITS(uname, lname)				\
static inline int Pcache##uname(const struct pcache_meta *p)	\
{								\
	return test_bit(PC_##lname, (void *)&p->bits);		\
}

#define SET_PC_BITS(uname, lname)				\
static inline void SetPcache##uname(struct pcache_meta *p)	\
{								\
	set_bit(PC_##lname, (void *)&p->bits);			\
}

#define CLEAR_PC_BITS(uname, lname)				\
static inline void ClearPcache##uname(struct pcache_meta *p)	\
{								\
	clear_bit(PC_##lname, (void *)&p->bits);		\
}

#define __SET_PC_BITS(uname, lname)				\
static inline void __SetPcache##uname(struct pcache_meta *p)	\
{								\
	__set_bit(PC_##lname, (void *)&p->bits);		\
}

#define __CLEAR_PC_BITS(uname, lname)				\
static inline void __ClearPcache##uname(struct pcache_meta *p)	\
{								\
	__clear_bit(PC_##lname, (void *)&p->bits);		\
}

#define TEST_SET_BITS(uname, lname)				\
static inline int TestSetPcache##uname(struct pcache_meta *p)	\
{								\
	return test_and_set_bit(PC_##lname, (void *)&p->bits);	\
}

#define TEST_CLEAR_BITS(uname, lname)				\
static inline int TestClearPcache##uname(struct pcache_meta *p)	\
{								\
	return test_and_clear_bit(PC_##lname, (void *)&p->bits);\
}

#define __TEST_SET_BITS(uname, lname)				\
static inline int __TestSetPcache##uname(struct pcache_meta *p)	\
{								\
	return __test_and_set_bit(PC_##lname, (void *)&p->bits);\
}

#define __TEST_CLEAR_BITS(uname, lname)				\
static inline int __TestClearPcache##uname(struct pcache_meta *p)\
{								\
	return __test_and_clear_bit(PC_##lname, (void *)&p->bits);\
}

#define PCACHE_META_BITS(uname, lname)				\
	TEST_PC_BITS(uname, lname)				\
	SET_PC_BITS(uname, lname)				\
	CLEAR_PC_BITS(uname, lname)				\
	__SET_PC_BITS(uname, lname)				\
	__CLEAR_PC_BITS(uname, lname)				\
	TEST_SET_BITS(uname, lname)				\
	TEST_CLEAR_BITS(uname, lname)				\
	__TEST_SET_BITS(uname, lname)				\
	__TEST_CLEAR_BITS(uname, lname)

PCACHE_META_BITS(Locked, locked)
PCACHE_META_BITS(Allocated, allocated)
PCACHE_META_BITS(Usable, usable)
PCACHE_META_BITS(Valid, valid)
PCACHE_META_BITS(Dirty, dirty)
PCACHE_META_BITS(Reclaim, reclaim)
PCACHE_META_BITS(Writeback, writeback)

static inline void pcache_reset_flags(struct pcache_meta *pcm)
{
	/*
	 * Once the Allocated bit is 0, this pcache line is returned
	 * to free pool. prep_new_pcache_meta() will initialize the
	 * pcm properly at next allocation time.
	 */
	smp_wmb();
	pcm->bits = 0;
}

/*
 * Flags checked when a pcache is freed.
 * Pcache lines being freed should not have these flags set.
 * It they are, there is a problem.
 * Basically, everything except Allocated & Usable
 */
#define PCACHE_FLAGS_CHECK_AT_FREE				\
	(1UL << PC_locked | 1UL << PC_valid | 1UL << PC_dirty |	\
	 1UL << PC_reclaim | 1UL << PC_writeback )

#endif /* _LEGO_PROCESSOR_PCACHE_TYPES_H_ */
