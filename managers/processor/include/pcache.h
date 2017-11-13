/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _COMPONENT_PROCESSOR_PCACHE_H_
#define _COMPONENT_PROCESSOR_PCACHE_H_

#include <lego/const.h>
#include <lego/bitops.h>
#include <lego/spinlock.h>

struct pcache_meta;

#define PCACHE_LINE_SIZE_SHIFT		(CONFIG_PCACHE_LINE_SIZE_SHIFT)
#define PCACHE_ASSOCIATIVITY_SHIFT	(CONFIG_PCACHE_ASSOCIATIVITY_SHIFT)

#define PCACHE_LINE_SIZE		(_AC(1,UL) << PCACHE_LINE_SIZE_SHIFT)
#define PCACHE_ASSOCIATIVITY		(_AC(1,UL) << PCACHE_ASSOCIATIVITY_SHIFT)
#define PCACHE_META_SIZE		(sizeof(struct pcache_meta))

extern u64 llc_cache_start;
extern u64 llc_cache_registered_size;

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

/* Given an user virtual address, return its set index number */
static inline unsigned long __addr2set(unsigned long address)
{
	return (address & pcache_set_mask) >> nr_bits_cacheline;
}

/**
 * struct pcache_set	- Metadata for each cache set
 * @lock: protecting allocation of lines within this set
 *
 * FAT NOTE:
 * If you add anything here, do not forget to check if this
 * new field needs to be initialized in init_pcache_set_map().
 */
struct pcache_set {
	spinlock_t	lock;
};

extern struct pcache_set *pcache_set_map;

/**
 * pcache_addr2set
 * @address: address in question
 *
 * Given an user virtual address, find its corresponding set.
 * Return struct pcache_set for this set, which is unique for every set.
 */
static inline struct pcache_set *pcache_addr2set(unsigned long address)
{
	return pcache_set_map + __addr2set(address);
}

/**
 * struct pcache_meta	- Metadata about one pcache line
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
	u8 bits;
} ____cacheline_aligned;

/*
 * pcacheline->bits
 *
 * PC_locked:		Pcacheline is locked. DO NOT TOUCH.
 * PC_allocated:	Pcacheline is allocated, but may not be valid.
 * PC_valid:		Pcacheline has a valid mapping and content.
 * PC_dirty:		Pcacheline is dirty
 */
enum pcache_meta_bits {
	PC_locked,
	PC_allocated,
	PC_valid,
	PC_dirty,

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
PCACHE_META_BITS(Valid, valid)
PCACHE_META_BITS(Dirty, dirty)

extern struct pcache_meta *pcache_meta_map;

/*
 * Given an user virtual address, return the first cache line within
 * its corresponding set. This can be used to walk through a set.
 *
 * Not public APIs!
 */
static inline struct pcache_meta *__addr2meta(unsigned long address)
{
	return pcache_meta_map + __addr2set(address);
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
 * Given the va/pa of cacheline's meta/data line, return the next way's
 * corresponding address, within the same set.
 *
 * Not public APIs!
 */
static inline struct pcache_meta *__pmeta_next_way(struct pcache_meta *p)
{
	return p + nr_cachesets;
}

static inline unsigned long __pline_va_next_way(unsigned long address)
{
	return address + pcache_way_cache_stride;
}

static inline unsigned long __pline_pa_next_way(unsigned long address)
{
	return address + pcache_way_cache_stride;
}

/*
 * Walk through N-way cache clines within a set
 * @pcache: struct pcache_meta as indicator
 * @way: current way
 * @address: address in question
 */
#define for_each_way_set(pcache, way, address)			\
	for (pcache = __addr2meta(address), way = 0;		\
	     way < PCACHE_ASSOCIATIVITY;			\
	     pcache = __pmeta_next_way(pcache), way++)

/* Given a @pcm, return its corresponding cacheline's physical address */
static inline void *pcache_meta_to_pa(struct pcache_meta *pcm)
{
	unsigned long offset = pcm - pcache_meta_map;

	BUG_ON(offset >= nr_cachelines);
	return (void *) (phys_start_cacheline + offset * PCACHE_LINE_SIZE);
}

/* Given a @pcm, return its corresponding cacheline's virtual address */
static inline void *pcache_meta_to_va(struct pcache_meta *pcm)
{
	unsigned long offset = pcm - pcache_meta_map;

	BUG_ON(offset >= nr_cachelines);
	return (void *) (virt_start_cacheline + offset * PCACHE_LINE_SIZE);
}

static inline unsigned long pcache_meta_to_pfn(struct pcache_meta *pcm)
{
	return ((unsigned long)pcache_meta_to_pa(pcm)) >> PCACHE_LINE_SIZE_SHIFT;
}

static inline pte_t pcache_meta_mk_pte(struct pcache_meta *pcm, pgprot_t pgprot)
{
	return pfn_pte(pcache_meta_to_pfn(pcm), pgprot);
}

/* Public APIs: allocate/free cachelines based on address pointed set */
struct pcache_meta *pcache_alloc(unsigned long address);
void pcache_free(struct pcache_meta *p);

#endif /* _COMPONENT_PROCESSOR_PCACHE_H_ */
