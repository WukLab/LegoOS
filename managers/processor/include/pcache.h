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

extern u64 llc_cache_start;
extern u64 llc_cache_registered_size;

/* Final used size */
extern u64 llc_cache_size;

extern u32 llc_cacheline_size;
extern u32 llc_cachemeta_size;

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
extern u64 virt_start_metadata;

/* Address bits usage */
extern u64 nr_bits_cacheline;
extern u64 nr_bits_set;
extern u64 nr_bits_tag;

extern u64 pcache_cacheline_mask;
extern u64 pcache_set_mask;
extern u64 pcache_tag_mask;

extern u64 pcache_way_cache_stride;
extern u64 pcache_way_meta_stride;

/*
 * Given an user virtual address, return its set number.
 */
static inline unsigned long addr2set(unsigned long addr)
{
	return (addr & pcache_set_mask) >> nr_bits_cacheline;
}

/*
 * Given an user virtual address, find the corresponding cacheline
 * metadata, return metadata's kernel virtual address
 */
static inline unsigned long addr2meta(unsigned long addr)
{
	return addr2set(addr) * llc_cachemeta_size;
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
	for (va_cache = (void *)((addr & pcache_set_mask) + virt_start_cacheline),	\
	     pa_cache = (void *)((addr & pcache_set_mask) + phys_start_cacheline),	\
	     va_meta = (void *)(addr2meta(addr) + virt_start_metadata), way = 0;	\
	     way < llc_cache_associativity;						\
	     way++,									\
	     pa_cache += pcache_way_cache_stride, 					\
	     va_cache += pcache_way_cache_stride, 					\
	     va_meta += pcache_way_meta_stride)

/*
 * Cacheline metadata definition and helpers:
 */

/* Cacheline metadata bits layout: */
#define _PCACHE_BIT_VALID	0
#define _PCACHE_BIT_DIRTY	1
#define _PCACHE_BIT_ACCESSED	2
#define _PCACHE_BIT_NX		3

#define _PCACHE_VALID		(_AT(unsigned long, 1) << _PCACHE_BIT_VALID)
#define _PCACHE_DIRTY		(_AT(unsigned long, 1) << _PCACHE_BIT_DIRTY)
#define _PCACHE_ACCESSED	(_AT(unsigned long, 1) << _PCACHE_BIT_ACCESSED)
#define _PCACHE_NX		(_AT(unsigned long, 1) << _PCACHE_BIT_NX)

static inline int __pcache_valid(unsigned long meta)
{
	return meta & _PCACHE_VALID;
}

static inline int __pcache_dirty(unsigned long meta)
{
	return meta & _PCACHE_DIRTY;
}

static inline int __pcache_accessed(unsigned long meta)
{
	return meta & _PCACHE_ACCESSED;
}

static inline int __pcache_nx(unsigned long meta)
{
	return meta & _PCACHE_NX;
}

#define pcache_valid(meta)	__pcache_valid(*(unsigned long *)meta)
#define pcache_dirty(meta)	__pcache_dirty(*(unsigned long *)meta)
#define pcache_accessed(meta)	__pcache_accessed(*(unsigned long *)meta)
#define pcache_nx(meta)		__pcache_nx(*(unsigned long *)meta)

static inline void __pcache_mkvalid(unsigned long *meta)
{
	*meta |= _PCACHE_VALID;
}

static inline void __pcache_mkdirty(unsigned long *meta)
{
	*meta |= _PCACHE_DIRTY;
}

static inline void __pcache_mkaccessed(unsigned long *meta)
{
	*meta |= _PCACHE_ACCESSED;
}

static inline void __pcache_mknx(unsigned long *meta)
{
	*meta |= _PCACHE_NX;
}

#define pcache_mkvalid(meta)	__pcache_mkvalid((unsigned long *)meta)
#define pcache_mkdirty(meta)	__pcache_mkdirty((unsigned long *)meta)
#define pcache_mkaccessed(meta)	__pcache_mkaccessed((unsigned long *)meta)
#define pcache_mknx(meta)	__pcache_mknx((unsigned long *)meta)

#endif /* _COMPONENT_PROCESSOR_PCACHE_H_ */
