/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROCESSOR_PCACHE_H_
#define _LEGO_PROCESSOR_PCACHE_H_

#include <lego/list.h>
#include <lego/const.h>
#include <lego/bitops.h>
#include <lego/jiffies.h>
#include <lego/spinlock.h>

#include <processor/pcache_types.h>
#include <processor/pcache_stat.h>
#include <processor/pcache_debug.h>
#include <uapi/processor/pcache.h>

extern u64 pcache_registered_start;
extern u64 pcache_registered_size;

/* Final used size */
extern u64 llc_cache_size;

/* nr_cachelines = nr_cachesets * associativity */
extern u64 nr_cachelines;
extern u64 nr_cachesets;

/* pages used by cacheline and metadata */
extern u64 nr_pages_cacheline;
extern u64 nr_pages_metadata;

/* original physical and ioremap'd virtual address */
extern u64 phys_start_cacheline;
extern u64 phys_start_metadata;
extern u64 virt_start_cacheline;

/* Address bits usage */
extern u64 nr_bits_cacheline;
extern u64 nr_bits_set;
extern u64 nr_bits_tag;

extern u64 pcache_cacheline_mask;
extern u64 pcache_set_mask;
extern u64 pcache_tag_mask;

extern u64 pcache_way_cache_stride;

/* pcache_set and pcache_meta array base */
extern struct pcache_set *pcache_set_map;
extern struct pcache_meta *pcache_meta_map;

/**
 * user_vaddr_to_set_index
 *
 * Given an user virtual address, return its set index number
 */
static inline unsigned long user_vaddr_to_set_index(unsigned long address)
{
	return (address & pcache_set_mask) >> nr_bits_cacheline;
}

static inline int trylock_pcache(struct pcache_meta *pcm)
{
#ifdef CONFIG_DEBUG_PCACHE
	int ret;

	ret = TestSetPcacheLocked(pcm);
	if (!ret)
		pcm->locker = current;
	return !ret;
#else
	return (likely(!TestSetPcacheLocked(pcm)));
#endif
}

static inline void lock_pcache(struct pcache_meta *pcm)
{
#ifdef CONFIG_DEBUG_PCACHE
	unsigned long wait_start = jiffies;

	while (unlikely(TestSetPcacheLocked(pcm))) {
		cpu_relax();

		/* Break out after 10 seconds */
		if (unlikely(time_after(jiffies, wait_start + 10 * HZ))) {
			dump_pcache_meta(pcm, "deadlock");
			pr_info("Locked by %s %d\n",
				pcm->locker->comm, pcm->locker->pid);
			BUG();
		}
	}
	pcm->locker = current;
#else
	while (unlikely(TestSetPcacheLocked(pcm)))
		cpu_relax();
#endif
}

static inline void unlock_pcache(struct pcache_meta *pcm)
{
#ifdef CONFIG_DEBUG_PCACHE
	pcm->locker = NULL;
	if (!TestClearPcacheLocked(pcm)) {
		dump_pcache_meta(pcm, "unlock bug");
		BUG();
	}
#else
	ClearPcacheLocked(pcm);
#endif
}

/* refcount helpers */
static inline int pcache_ref_count(struct pcache_meta *p)
{
	return atomic_read(&p->_refcount);
}

static inline void pcache_ref_count_set(struct pcache_meta *p, int v)
{
	atomic_set(&p->_refcount, v);
}

static inline void init_pcache_ref_count(struct pcache_meta *p)
{
	pcache_ref_count_set(p, 1);
}

static inline void pcache_ref_count_inc(struct pcache_meta *p)
{
	atomic_inc(&p->_refcount);
}

static inline void pcache_ref_count_dec(struct pcache_meta *p)
{
	atomic_dec(&p->_refcount);
}

static inline void pcache_ref_sub(struct pcache_meta *p, int nr)
{
	atomic_sub(nr, &p->_refcount);
}

static inline int pcache_ref_count_dec_and_test(struct pcache_meta *p)
{
	return atomic_dec_and_test(&p->_refcount);
}

static inline int pcache_ref_count_add_unless(struct pcache_meta *p, int nr, int u)
{
	return atomic_add_unless(&p->_refcount, nr, u);
}

/* Return true if value drops to 0 */
static inline int pcache_ref_sub_and_test(struct pcache_meta *p, int nr)
{
	int ret = atomic_sub_and_test(nr, &p->_refcount);
	return ret;
}

/* Return true if the original value equals @count */
static inline int pcache_ref_freeze(struct pcache_meta *p, int count)
{
	int ret = likely(atomic_cmpxchg(&p->_refcount, count, 0) == count);
	return ret;
}

/* Grab a ref */
static inline void get_pcache(struct pcache_meta *p)
{
	/*
	 * Getting a normal pcache requires to already have
	 * an elevated pcache->_refcount, which is set by allocator.
	 */
	PCACHE_BUG_ON_PCM(pcache_ref_count(p) <= 0, p);
	pcache_ref_count_inc(p);
}

/*
 * Try to grab a ref unless the pcache line has a refcount of zero,
 * return false if that is the case.
 */
static inline int get_pcache_unless_zero(struct pcache_meta *p)
{
	return pcache_ref_count_add_unless(p, 1, 0);
}

/* Drop a ref, return true if refcount fell to 0 (the pcache has no users) */
static inline int put_pcache_testzero(struct pcache_meta *p)
{
	PCACHE_BUG_ON_PCM(pcache_ref_count(p) == 0, p);
	return pcache_ref_count_dec_and_test(p);
}

void __put_pcache_nolru(struct pcache_meta *pcm);
void __put_pcache(struct pcache_meta *pcm);

static inline void put_pcache(struct pcache_meta *p)
{
	if (put_pcache_testzero(p))
		__put_pcache(p);
}

/* mapcount helpers */
static inline int pcache_mapcount(struct pcache_meta *pcm)
{
	return atomic_read(&pcm->mapcount);
}

static inline void pcache_mapcount_reset(struct pcache_meta *pcm)
{
	atomic_set(&pcm->mapcount, 0);
}

static inline bool pcache_mapped(struct pcache_meta *pcm)
{
	if (atomic_read(&pcm->mapcount) > 0)
		return true;
	return false;
}

/*
 * Atomically decrements mapcount by 1 and
 * returns true if the result is 0, or false for all other
 */
static inline bool pcache_mapcount_dec_and_test(struct pcache_meta *pcm)
{
	return atomic_dec_and_test(&pcm->mapcount);
}

/* physical address is one of pcache data lines? */
static inline bool pa_is_pcache(unsigned long address)
{
	if (likely(address >= phys_start_cacheline &&
		   address < phys_start_metadata))
		return true;
	return false;
}

/* kernel virtual address is one of pcache data lines? */
static inline bool kva_is_pcache(unsigned long address)
{
	if (likely(address >= virt_start_cacheline &&
		   address < (unsigned long)pcache_meta_map))
		return true;
	return false;
}

/*
 * Given an user virtual address, return the first cache line within
 * its corresponding set. This can be used to walk through a set.
 *
 * Not public APIs!
 */
static inline struct pcache_meta *__addr2meta(unsigned long address)
{
	return pcache_meta_map + user_vaddr_to_set_index(address);
}

static inline unsigned long __addr2line_va(unsigned long address)
{
	return virt_start_cacheline + (address & pcache_set_mask);
}

static inline unsigned long __addr2line_pa(unsigned long address)
{
	return phys_start_cacheline + (address & pcache_set_mask);
}

/*
 * Return the array index where @pcm maps into @pcache_meta_map
 * Internal function.
 */
static inline unsigned long __pcache_meta_index(struct pcache_meta *pcm)
{
	unsigned long offset;

	offset = pcm - pcache_meta_map;
	BUG_ON(offset >= nr_cachelines);
	return offset;
}

/**
 * pcache_meta_to_pcache_set
 * @pcm: pcache meta in question
 *
 * Given a @pcm, return the pcache_set that @pcm belongs to.
 * In all, there are PCACHE_ASSOCIATIVITY @pcm can map to the same set.
 */
static inline struct pcache_set *
pcache_meta_to_pcache_set(struct pcache_meta *pcm)
{
	unsigned long offset;

	offset = pcm - pcache_meta_map;
	BUG_ON(offset >= nr_cachelines);
	offset = offset % nr_cachesets;

	return pcache_set_map + offset;
}

static inline unsigned long
pcache_set_to_set_index(struct pcache_set *pset)
{
	unsigned long offset;

	offset = pset - pcache_set_map;
	BUG_ON(offset >= nr_cachesets);
	return offset;
}

/**
 * pcache_set_to_first_pcache_meta
 * @pset: pcache set in question
 *
 * Given a @pset, return the first way's pcache meta.
 */
static inline struct pcache_meta *
pcache_set_to_first_pcache_meta(struct pcache_set *pset)
{
	unsigned long offset;

	offset = pset - pcache_set_map;
	BUG_ON(offset >= nr_cachesets);
	return pcache_meta_map + offset;
}

/**
 * pcache_meta_to_pa
 * @pcm: pcache meta in question
 *
 * Given a @pcm, return its corresponding cacheline's physical address
 */
static inline void *pcache_meta_to_pa(struct pcache_meta *pcm)
{
	unsigned long offset = pcm - pcache_meta_map;

	BUG_ON(offset >= nr_cachelines);
	return (void *) (phys_start_cacheline + offset * PCACHE_LINE_SIZE);
}

/**
 * pcache_meta_to_kva
 * @pcm: pcache meta in question
 *
 * Given a @pcm, return its corresponding cacheline's kernel virtual address
 */
static inline void *pcache_meta_to_kva(struct pcache_meta *pcm)
{
	unsigned long offset = pcm - pcache_meta_map;

	BUG_ON(offset >= nr_cachelines);
	return (void *) (virt_start_cacheline + offset * PCACHE_LINE_SIZE);
}

/**
 * pa_to_pcache_meta
 * @address: physical address of the pcache data line
 *
 * Given a physical address, find its pcache meta.
 * If @address is not valid, return NULL
 */
static inline struct pcache_meta *
pa_to_pcache_meta(unsigned long address)
{
	if (likely(pa_is_pcache(address))) {
		unsigned long offset;

		offset = (address & PCACHE_LINE_MASK) - phys_start_cacheline;
		offset = offset >> PCACHE_LINE_SIZE_SHIFT;
		return pcache_meta_map + offset;
	}
	return NULL;
}

static inline __must_check struct pcache_meta *
pfn_to_pcache_meta(unsigned long pfn)
{
	unsigned long pa = pfn << PAGE_SHIFT;
	return pa_to_pcache_meta(pa);
}

static inline __must_check struct pcache_meta *
pte_to_pcache_meta(pte_t pte)
{
	unsigned long pa = pte_val(pte) & PTE_PFN_MASK;
	return pa_to_pcache_meta(pa);
}

/**
 * kva_to_pcache_meta
 * @address: kernel virtual address of the pcache data line
 *
 * Given a kernel virtual address, find its pcache meta.
 * If @address is not valid, return NULL
 */
static inline struct pcache_meta *kva_to_pcache_meta(unsigned long address)
{
	if (likely(kva_is_pcache(address))) {
		unsigned long offset;

		offset = (address & PCACHE_LINE_MASK) - virt_start_cacheline;
		offset = offset >> PCACHE_LINE_SIZE_SHIFT;
		return pcache_meta_map + offset;
	}
	return NULL;
}

/**
 * pa_to_pcache_set
 * @address: physical address of the pcache data line
 *
 * Given a physical address, find its pcache set.
 * If @address is not valid, return NULL
 */
static inline struct pcache_set *pa_to_pcache_set(unsigned long address)
{
	struct pcache_meta *pcm;

	pcm = pa_to_pcache_meta(address);
	if (likely(pcm))
		return pcache_meta_to_pcache_set(pcm);
	return NULL;
}

/**
 * kva_to_pcache_set
 * @address: kernel virtual address of the pcache data line
 *
 * Given a kernel virtual address, find its pcache set.
 * If @address is not valid, return NULL
 */
static inline struct pcache_set *kva_to_pcache_set(unsigned long address)
{
	struct pcache_meta *pcm;

	pcm = kva_to_pcache_meta(address);
	if (likely(pcm))
		return pcache_meta_to_pcache_set(pcm);
	return NULL;
}

/**
 * user_vaddr_to_pcache_set
 * @uvaddr: user virtual address in question
 *
 * Given an user virtual address, find its corresponding set.
 * Return struct pcache_set for this set, which is unique for every set.
 */
static inline struct pcache_set *
user_vaddr_to_pcache_set(unsigned long uvaddr)
{
	return pcache_set_map + user_vaddr_to_set_index(uvaddr);
}

static inline unsigned long pcache_meta_to_pfn(struct pcache_meta *pcm)
{
	return ((unsigned long)pcache_meta_to_pa(pcm)) >> PCACHE_LINE_SIZE_SHIFT;
}

static inline pte_t pcache_mk_pte(struct pcache_meta *pcm, pgprot_t pgprot)
{
	return pfn_pte(pcache_meta_to_pfn(pcm), pgprot);
}

/*
 * Create and return a new pte,
 * use the same pgprot attributes with @old_pte
 */
static inline pte_t pcache_dup_pte_pgprot(struct pcache_meta *pcm, pte_t old_pte)
{
	pgprot_t pgprot = pte_pgprot(old_pte);;

	return pcache_mk_pte(pcm, pgprot);
}

static inline struct pcache_meta *
__pcache_meta_next_way(struct pcache_meta *pcm)
{
	return pcm + nr_cachesets;
}

static inline unsigned long
pcache_meta_to_way(struct pcache_meta *pcm)
{
	unsigned long offset, way;

	offset = pcm - pcache_meta_map;
	way = offset / nr_cachesets;
	BUG_ON(way >= PCACHE_ASSOCIATIVITY);
	return way;
}

/**
 * pcache_meta_next_way
 * @pcm: pcache meta in question
 *
 * Given a @pcm, return the next way's @pcm within same set.
 * If @pcm is already the last way, return NULL.
 */
static inline struct pcache_meta *
pcache_meta_next_way(struct pcache_meta *pcm)
{
	unsigned long offset, way_idx;

	offset = pcm - pcache_meta_map;
	BUG_ON(offset >= nr_cachelines);

	way_idx = offset / nr_cachesets;
	if (unlikely(way_idx >= PCACHE_ASSOCIATIVITY))
		return NULL;
	return __pcache_meta_next_way(pcm);
}

/*
 * Walk through all sets of pcache
 * Use with caution
 */
#define pcache_for_each_set(pset, nr)					\
	for (nr = 0, pset = pcache_set_map; nr < nr_cachesets;		\
	     nr++, pset++)

/*
 * Walk through all cache lines of pcache
 * Use with caution
 */
#define pcache_for_each_way(pcm, nr)					\
	for (nr = 0, pcm = pcache_meta_map; nr < nr_cachelines;		\
	     nr++, pcm++)

/*
 * Walk though all ways within a set
 * The maximum is PCACHE_ASSOCIATIVITY
 */
#define pcache_for_each_way_set(pcm, pset, way)				\
	for (pcm = pcache_set_to_first_pcache_meta(pset), way = 0;	\
	     way < PCACHE_ASSOCIATIVITY;				\
	     pcm = __pcache_meta_next_way(pcm), way++)

enum piggyback_options {
	DISABLE_PIGGYBACK,
	ENABLE_PIGGYBACK,
};

/* Allocate one pcache line from the pset @address maps to */
struct pcache_meta *pcache_alloc(unsigned long address,
				 enum piggyback_options piggyback);

int pcache_flush_one(struct pcache_meta *pcm);
void clflush_one(struct task_struct *tsk, unsigned long user_va, void *cache_addr);
void __clflush_one(pid_t tgid, unsigned long user_va,
		   unsigned int m_nid, unsigned int rep_nid, void *cache_addr);

/* eviction */
int pcache_evict_line(struct pcache_set *pset, unsigned long address,
		      enum piggyback_options piggyback);

#ifdef CONFIG_PCACHE_EVICTION_PERSET_LIST
bool __pset_find_eviction(struct pcache_set *, unsigned long, struct task_struct *);

static inline bool
pset_find_eviction(unsigned long uvaddr, struct task_struct *p)
{
	struct pcache_set *pset = user_vaddr_to_pcache_set(uvaddr);

	/*
	 * HACK!!!
	 *
	 * We are safe to JUST check counter here. The reason is simple:
	 * we first do insert and update counter, then we do unmap.
	 *
	 * This code path happen at pgfault time. It basically means
	 * either 1) the page has never been established, 2) the page
	 * has just been evicted. According to above, we are safe
	 * at both cases.
	 */
	if (likely(atomic_read(&pset->nr_eviction_entries) == 0))
		return false;

	/*
	 * We may have some false-positive here due to set-associated pcache.
	 * Should be fine...
	 */
	return __pset_find_eviction(pset, uvaddr, p);
}
#endif

/*
 * rmap_walk_control: To control rmap traversing for specific needs
 *
 * arg: passed to rmap_one()
 * rmap_one: executed on each rmap where pcache line is mapped
 * done: for checking traversing termination condition
 */
struct rmap_walk_control {
	void *arg;
	int (*rmap_one)(struct pcache_meta *, struct pcache_rmap *, void *);
	int (*done)(struct pcache_meta *);
};

enum pcache_rmap_status {
	PCACHE_RMAP_SUCCEED,
	PCACHE_RMAP_AGAIN,
	PCACHE_RMAP_FAILED,
};

int pcache_zap_pte(struct mm_struct *mm, unsigned long address,
		   pte_t ptent, pte_t *pte, spinlock_t *ptl);
int pcache_move_pte(struct mm_struct *mm, pte_t *old_pte, pte_t *new_pte,
		    unsigned long old_addr, unsigned long new_addr, spinlock_t *old_ptl);

int pcache_add_rmap(struct pcache_meta *pcm, pte_t *page_table,
		    unsigned long address, struct mm_struct *owner_mm,
		    struct task_struct *owner_process,
		    enum rmap_caller caller);

void pcache_remove_rmap(struct pcache_meta *pcm, pte_t *ptep, unsigned long address,
			struct mm_struct *owner_mm, struct task_struct *owner_process);

#ifdef CONFIG_COMP_PROCESSOR
/* Called when fork() happens, duplicate the pcache */
int fork_dup_pcache(struct task_struct *dst_task,
		    struct mm_struct *dst_mm, struct mm_struct *src_mm, void *_vmainfo);
void __init pcache_print_info(void);
#else
static inline int fork_dup_pcache(struct task_struct *t,
				  struct mm_struct *m1, struct mm_struct *m2,
				  void *_vmainfo)
{
	return 0;
}

static inline void pcache_print_info(void) { }
#endif

int rmap_walk(struct pcache_meta *pcm, struct rmap_walk_control *rwc);
int pcache_try_to_unmap(struct pcache_meta *pcm);
bool pcache_try_to_unmap_check_dirty(struct pcache_meta *pcm);
bool pcache_try_to_unmap_reserve_check_dirty(struct pcache_meta *pcm);
int pcache_wrprotect(struct pcache_meta *pcm);
int pcache_referenced(struct pcache_meta *pcm);
void pcache_referenced_trylock(struct pcache_meta *pcm,
			       int *pte_referenced, int *pte_contention);

int pcache_try_to_unmap_reserve(struct pcache_meta *pcm);
int pcache_free_reserved_rmap(struct pcache_meta *pcm);

typedef int (*fill_func_t)(unsigned long, unsigned long, struct pcache_meta *, void *);

int common_do_fill_page(struct mm_struct *mm, unsigned long address,
			pte_t *page_table, pte_t orig_pte, pmd_t *pmd,
			unsigned long flags, fill_func_t fill_func, void *arg,
			enum rmap_caller caller, enum piggyback_options piggyback);

#include <processor/pcache_victim.h>
#include <processor/pcache_evict.h>

#endif /* _LEGO_PROCESSOR_PCACHE_H_ */
