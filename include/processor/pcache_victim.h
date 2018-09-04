/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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

#include <lego/completion.h>

#define VICTIM_NR_ENTRIES \
	((unsigned int)CONFIG_PCACHE_EVICTION_VICTIM_NR_ENTRIES)

struct victim_padding {
	char x[0];
} ____cacheline_aligned_in_smp;
#define VICTIM_PADDING(name)	struct victim_padding name;

struct pcache_victim_meta {
	unsigned long		flags;
	VICTIM_PADDING(_pad1_);

	spinlock_t		lock;		/* protect list operations */

	/*
	 * Number of concurrent fill to pcache line.
	 * Shared lines may have multiple concurrent fill activities
	 * at the same time. One bit is not enough. This is used
	 * to sync with eviction routine.
	 */
	atomic_t		nr_fill_pcache;
	atomic_t		max_nr_fill_pcache;

	atomic_t		_refcount;

	/*
	 * Natually victim cache line does not map to any
	 * specific pcache lines. The short existence of pcm
	 * is just used to do two-step insertion.
	 *
	 * It will be reset to NULL after insertion finished.
	 */
	struct pcache_meta	*pcm;
	struct pcache_set	*pset;		/* pset this victim belongs to */
	struct list_head	hits;		/* history pid+addr users */

	/* Link to next allocated victim cache */
	struct list_head	next;

} ____cacheline_aligned_in_smp;

struct pcache_victim_hit_entry {
	unsigned long		address;	/* page aligned */
	pid_t			tgid;
	unsigned int		m_nid;
	unsigned int		rep_nid;
	struct list_head	next;
};

struct victim_flush_job {
	struct pcache_victim_meta *victim;
	struct completion done;
	bool wait;
	struct list_head next;
};

#ifdef CONFIG_PCACHE_EVICTION_VICTIM

static inline int victim_ref_count(struct pcache_victim_meta *v)
{
	return atomic_read(&v->_refcount);
}

static inline void victim_ref_count_set(struct pcache_victim_meta *v, int value)
{
	atomic_set(&v->_refcount, value);
}

static inline void victim_ref_count_inc(struct pcache_victim_meta *v)
{
	atomic_inc(&v->_refcount);
}

static inline void victim_ref_count_dec(struct pcache_victim_meta *v)
{
	atomic_dec(&v->_refcount);
}

static inline int
victim_ref_add_unless(struct pcache_victim_meta *v, int nr, int u)
{
	return atomic_add_unless(&v->_refcount, nr, u);
}

/* Return true if value drops to 0 */
static inline int victim_ref_sub_and_test(struct pcache_victim_meta *v, int nr)
{
	int ret = atomic_sub_and_test(nr, &v->_refcount);
	return ret;
}

/* Drop a ref, return true if ref drops to zero (no users) */
static inline int victim_ref_count_dec_and_test(struct pcache_victim_meta *v)
{
	return atomic_dec_and_test(&v->_refcount);
}

/*
 * Try to grab a ref unless the victim has a refcount of zero,
 * return false if that is the case. Return true if ref increased.
 */
static inline int get_victim_unless_zero(struct pcache_victim_meta *v)
{
	return victim_ref_add_unless(v, 1, 0);
}

static inline void get_victim(struct pcache_victim_meta *v)
{
	victim_ref_count_inc(v);
}

void __put_victim(struct pcache_victim_meta *v);

/* Drop a ref, return true if refcount fell to 0 (the victim has no users) */
static inline int put_victim_testzero(struct pcache_victim_meta *v)
{
	PCACHE_BUG_ON_VICTIM(victim_ref_count(v) == 0, v);
	return victim_ref_count_dec_and_test(v);
}

static inline void put_victim(struct pcache_victim_meta *v)
{
	if (put_victim_testzero(v))
		__put_victim(v);
}

/* Return true if the original value equals @count */
static inline int victim_ref_freeze(struct pcache_victim_meta *v, int count)
{
	int ret = likely(atomic_cmpxchg(&v->_refcount, count, 0) == count);
	return ret;
}

extern struct pcache_victim_meta pcache_victim_meta_map[VICTIM_NR_ENTRIES];
extern void *pcache_victim_data_map;

/*
 * Only allocation routine can use this macro.
 * Others have to use allocated victim list.
 */
#define for_each_victim(victim, index)				\
	for (index = 0, victim = pcache_victim_meta_map;	\
	     index < VICTIM_NR_ENTRIES;				\
	     index++, victim++)

/*
 * victim_meta->flags
 *
 * PCACHE_VICTIM_locked:	victim cache locked. DO NOT TOUCH.
 * PCACHE_VICTIM_allocated:	victim cache is allocated
 * PCACHE_VICTIM_usable:	victim cache is usable for all users
 * PCACHE_VICTIM_hasdata:	victim cache has real data in its line
 * 				Set once the second step of insertion finished.
 *
 * PCACHE_VICTIM_writeback:	victim cache is being written to memory
 * 				Set when the victim is under clflush routine.
 * 				This is a pure debug flag
 *
 * PCACHE_VICTIM_waitflush:	victim cache has been submitted to flush queue
 * 				waiting to be flushed. Exclusive with flushed flag.
 * 				This is a pure debug flag
 *
 * PCACHE_VICTIM_flushed:	victim cache has been flushed back
 * 				This is used be victim eviction routine to select
 * 				condidate.
 *
 * PCACHE_VICTIM_reclaim:	victim cache is selected to be evicted, but not yet
 *
 * PCACHE_VICTIM_fillfree:	victim cache can only be freed by fill path.
 * 				Eviction routine should skip this line!
 *
 * PCACHE_VICTIM_nohit:		victim is going to be freed by a concurrent thread.
 * 				It does not allow any hit anymore. Whatever the result is,
 * 				the caller should skip checking victim.
 *
 * Hack: remember to update the victimflag_names array in debug file.
 */
enum pcache_victim_flags {
	PCACHE_VICTIM_locked,
	PCACHE_VICTIM_allocated,
	PCACHE_VICTIM_usable,
	PCACHE_VICTIM_hasdata,
	PCACHE_VICTIM_writeback,
	PCACHE_VICTIM_waitflush,
	PCACHE_VICTIM_flushed,
	PCACHE_VICTIM_reclaim,
	PCACHE_VICTIM_fillfree,
	PCACHE_VICTIM_nohit,

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

#define __SET_VICTIM_FLAGS(uname, lname)				\
static inline void __SetVictim##uname(struct pcache_victim_meta *p)	\
{									\
	__set_bit(PCACHE_VICTIM_##lname, &p->flags);			\
}

#define __CLEAR_VICTIM_FLAGS(uname, lname)				\
static inline void __ClearVictim##uname(struct pcache_victim_meta *p)	\
{									\
	__clear_bit(PCACHE_VICTIM_##lname, &p->flags);			\
}

#define VICTIM_FLAGS(uname, lname)					\
	TEST_VICTIM_FLAGS(uname, lname)					\
	SET_VICTIM_FLAGS(uname, lname)					\
	__SET_VICTIM_FLAGS(uname, lname)				\
	CLEAR_VICTIM_FLAGS(uname, lname)				\
	__CLEAR_VICTIM_FLAGS(uname, lname)				\
	TEST_SET_VICTIM_BITS(uname, lname)				\
	TEST_CLEAR_VICTIM_BITS(uname, lname)

VICTIM_FLAGS(Locked, locked)
VICTIM_FLAGS(Allocated, allocated)
VICTIM_FLAGS(Usable, usable)
VICTIM_FLAGS(Hasdata, hasdata)
VICTIM_FLAGS(Writeback, writeback)
VICTIM_FLAGS(Waitflush, waitflush)
VICTIM_FLAGS(Flushed, flushed)
VICTIM_FLAGS(Reclaim, reclaim)
VICTIM_FLAGS(Fillfree, fillfree)
VICTIM_FLAGS(Nohit, nohit)

static inline void lock_victim(struct pcache_victim_meta *victim)
{
	while (TestSetVictimLocked(victim))
		cpu_relax();
}

static inline void unlock_victim(struct pcache_victim_meta *victim)
{
	BUG_ON(!VictimLocked(victim));
	ClearVictimLocked(victim);
}

static inline void set_victim_usable(struct pcache_victim_meta *victim)
{
	SetVictimUsable(victim);
	barrier();
}

struct pcache_victim_meta *
victim_prepare_insert(struct pcache_set *pset, struct pcache_meta *pcm, unsigned long address);
void victim_finish_insert(struct pcache_victim_meta *victim, bool dirty);

static inline unsigned int victim_index(struct pcache_victim_meta *victim)
{
	unsigned int index = victim - pcache_victim_meta_map;

	BUG_ON(index >= VICTIM_NR_ENTRIES);
	return index;
}

/**
 * pcache_victim_to_kva
 * @victim: victim cache line in question
 *
 * Return victim cache line's kernel virtual address.
 */
static inline void *pcache_victim_to_kva(struct pcache_victim_meta *victim)
{
	unsigned int index;

	index = victim_index(victim);
	return (void *) (pcache_victim_data_map + index * PCACHE_LINE_SIZE);
}

int victim_submit_flush(struct pcache_victim_meta *victim, bool wait, bool dirty);

/* Submit a flush job to flush thread, return immediately */
static inline int 
victim_submit_flush_nowait(struct pcache_victim_meta *victim, bool dirty)
{
	return victim_submit_flush(victim, false, dirty);
}

/* Submit a flush job to flush thread, wait until flushed back */
static inline int
victim_submit_flush_wait(struct pcache_victim_meta *victim, bool dirty)
{
	return victim_submit_flush(victim, true, dirty);
}

int victim_flush_sync(void);

static inline void pcache_set_victim_inc(struct pcache_set *pset)
{
	atomic_inc(&pset->nr_victims);
}

static inline void pcache_set_victim_dec(struct pcache_set *pset)
{
	atomic_dec(&pset->nr_victims);
}

static inline int pcache_set_victim_nr(struct pcache_set *pset)
{
	return atomic_read(&pset->nr_victims);
}

static inline bool pcache_set_has_victims(struct pcache_set *pset)
{
	if (atomic_read(&pset->nr_victims) > 0)
		return true;
	return false;
}

static inline bool victim_may_hit(unsigned long address)
{
	struct pcache_set *pset;

	pset = user_vaddr_to_pcache_set(address);
	if (pcache_set_has_victims(pset))
		return true;
	return false;
}

int victim_try_fill_pcache(struct mm_struct *mm, unsigned long address,
			   pte_t *page_table, pte_t orig_pte, pmd_t *pmd,
			   unsigned long flags);

/*
 * nr_fill_pcache helpers:
 */

static inline void inc_victim_filling(struct pcache_victim_meta *victim)
{
	atomic_inc(&victim->nr_fill_pcache);

	if (atomic_read(&victim->nr_fill_pcache) > atomic_read(&victim->max_nr_fill_pcache))
		atomic_set(&victim->max_nr_fill_pcache, atomic_read(&victim->nr_fill_pcache));
}

static inline void dec_victim_filling(struct pcache_victim_meta *victim)
{
	atomic_dec(&victim->nr_fill_pcache);
}

/* Return true if the result after dec is 0 */
static inline int
dec_and_test_victim_filling(struct pcache_victim_meta *victim)
{
	PCACHE_BUG_ON_VICTIM(atomic_read(&victim->nr_fill_pcache) == 0, victim);
	return atomic_dec_and_test(&victim->nr_fill_pcache);
}

static inline bool victim_is_filling(struct pcache_victim_meta *victim)
{
	if (atomic_read(&victim->nr_fill_pcache) > 0)
		return true;
	return false;
}

void __init victim_cache_early_init(void);
void __init victim_cache_post_init(void);

extern atomic_t nr_flush_jobs;
extern spinlock_t victim_flush_lock;
extern struct list_head victim_flush_queue;

static inline int nr_flush_queue_jobs(void)
{
	return atomic_read(&nr_flush_jobs);
}

void dump_victim_flush_queue(void);
void dump_all_victim(void);
void dump_victim_lines_and_queue(void);

void dump_pcache_victim(struct pcache_victim_meta *victim, const char *reason);
void dump_pcache_victim_simple(struct pcache_victim_meta *victim);
void dump_pcache_victim_hits(struct pcache_victim_meta *victim);

struct victim_flush_job *__steal_victim_flush_job(void);

static __always_inline struct victim_flush_job *steal_victim_flush_job(void)
{
	if (nr_flush_queue_jobs())
		return __steal_victim_flush_job();
	return NULL;
}

#else
static inline void victim_cache_early_init(void) { }
static inline void victim_cache_post_init(void) { }
#endif /* CONFIG_PCACHE_EVICTION_VICTIM */

#endif /* _LEGO_PROCESSOR_PCACHE_VICTIM_H_ */
