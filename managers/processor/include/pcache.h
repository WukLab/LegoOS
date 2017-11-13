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

#include <lego/bitops.h>
#include <lego/spinlock.h>

struct pcache_meta;

extern u64 llc_cache_start;
extern u64 llc_cache_registered_size;

/* Final used size */
extern u64 llc_cache_size;

extern u32 llc_cacheline_size;

/* nr_cachelines = nr_cachesets * associativity */
extern u64 nr_cachelines;
extern u64 nr_cachesets;
extern u32 llc_cache_associativity;

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
extern u64 pcache_way_meta_stride;

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

static inline struct pcache_set *pcache_addr2set(unsigned long address)
{
	return pcache_set_map + __addr2set(address);
}

/**
 * struct pcache_meta	- Metadata about one pcache line
 *
 * You can think this structure as the traditional metadata
 * part for a cache line, but with some addtional fields.
 *
 * Note that this structure is *CPU cacheline size* aligned
 * to minimize CPU cacheline pingpong between different cores.
 */
struct pcache_meta {
	u8 bits;
} ____cacheline_aligned;

/*
 * pcacheline->bits
 *
 * PC_locked:		Pcacheline is locked. DO NOT TOUCH.
 * PC_valid:		Pcacheline is valid
 * PC_dirty:		Pcacheline is dirty
 */
enum pcache_meta_bits {
	PC_locked,
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
PCACHE_META_BITS(Valid, valid)
PCACHE_META_BITS(Dirty, dirty)

extern struct pcache_meta *virt_start_metadata;

/*
 * Given an user virtual address, return the first cache line within
 * its corresponding set. This can be used to walk through a set.
 */
static inline struct pcache_meta *pcache_addr2meta(unsigned long address)
{
	return virt_start_metadata + __addr2set(address);
}

static inline unsigned long pcache_addr2line_va(unsigned long address)
{
	return (address & pcache_set_mask) + virt_start_cacheline;
}

static inline unsigned long pcache_addr2line_pa(unsigned long address)
{
	return (address & pcache_set_mask) + phys_start_cacheline;
}

/*
 * Walk through all N-way cachelines within a set
 * @addr: the address in question
 * @pa_cache: physical address of the cacheline 
 * @va_cache: virtual address of the cacheline 
 * @va_meta: virtual address of the metadata
 * @way: current way number (maximum is llc_cache_associativity)
 */
#define for_each_way_set(addr, pa_cache, va_cache, va_meta, way)			\
	for (va_cache = (void *)(pcache_addr2line_va(addr)),				\
	     pa_cache = (void *)(pcache_addr2line_pa(addr)),				\
	     va_meta = (void *)(pcache_addr2meta(addr)), way = 0;			\
	     way < llc_cache_associativity;						\
	     way++,									\
	     pa_cache += pcache_way_cache_stride, 					\
	     va_cache += pcache_way_cache_stride, 					\
	     va_meta += pcache_way_meta_stride)

#endif /* _COMPONENT_PROCESSOR_PCACHE_H_ */
