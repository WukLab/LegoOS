/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROCESSOR_PCACHE_H_
#define _LEGO_PROCESSOR_PCACHE_H_

#include <lego/const.h>
#include <lego/bitops.h>
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
extern unsigned long *pcache_set_eviction_bitmap;

/* Given an user virtual address, return its set index number */
static inline unsigned long __uvaddr2set(unsigned long address)
{
	return (address & pcache_set_mask) >> nr_bits_cacheline;
}

void unlock_pcache(struct pcache_meta *pcm);
void __lock_pcache(struct pcache_meta *pcm);

static inline int trylock_pcache(struct pcache_meta *pcm)
{
	return (likely(!test_and_set_bit(PC_locked, (void *)&pcm->bits)));
}

static inline void lock_pcache(struct pcache_meta *pcm)
{
	might_sleep();
	if (!trylock_pcache(pcm))
		__lock_pcache(pcm);
}

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
	return pcache_meta_map + __uvaddr2set(address);
}

static inline unsigned long __addr2line_va(unsigned long address)
{
	return virt_start_cacheline + (address & pcache_set_mask);
}

static inline unsigned long __addr2line_pa(unsigned long address)
{
	return phys_start_cacheline + (address & pcache_set_mask);
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
	return pcache_set_map + __uvaddr2set(uvaddr);
}

#ifdef CONFIG_PCACHE_EVICTION_LIST
static inline bool
pset_has_eviction(unsigned long uvaddr)
{
	return test_bit(__uvaddr2set(uvaddr), pcache_set_eviction_bitmap);
}
bool pset_find_eviction(unsigned long uvaddr, struct task_struct *tsk);
#endif

static inline unsigned long pcache_meta_to_pfn(struct pcache_meta *pcm)
{
	return ((unsigned long)pcache_meta_to_pa(pcm)) >> PCACHE_LINE_SIZE_SHIFT;
}

static inline pte_t pcache_meta_mk_pte(struct pcache_meta *pcm, pgprot_t pgprot)
{
	return pfn_pte(pcache_meta_to_pfn(pcm), pgprot);
}

static inline struct pcache_meta *
__pcache_meta_next_way(struct pcache_meta *pcm)
{
	return pcm + nr_cachesets;
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

#define for_each_way_set(pcm, pset, way)				\
	for (pcm = pcache_set_to_first_pcache_meta(pset), way = 0;	\
	     way < PCACHE_ASSOCIATIVITY;				\
	     pcm = __pcache_meta_next_way(pcm), way++)

/* Public APIs: allocate/free cachelines based on address pointed set */
struct pcache_meta *pcache_alloc(unsigned long address);
void pcache_free(struct pcache_meta *);

/* clflush */
int pcache_flush_one(struct pcache_meta *pcm);

/* eviction */
int pcache_evict_line(struct pcache_set *pset, unsigned long address);

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

int pcache_add_rmap(struct pcache_meta *pcm, pte_t *page_table, unsigned long address);
int rmap_walk(struct pcache_meta *pcm, struct rmap_walk_control *rwc);
int pcache_try_to_unmap(struct pcache_meta *pcm);
int pcache_wrprotect(struct pcache_meta *pcm);

#endif /* _LEGO_PROCESSOR_PCACHE_H_ */
