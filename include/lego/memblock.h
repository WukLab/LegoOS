/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MEMBLOCK_H_
#define _LEGO_MEMBLOCK_H_

#include <lego/types.h>
#include <lego/numa.h>

#define INIT_MEMBLOCK_REGIONS	128

/* Definition of memblock flags. */
enum {
	MEMBLOCK_NONE		= 0x0,	/* No special request */
	MEMBLOCK_HOTPLUG	= 0x1,	/* hotpluggable region */
	MEMBLOCK_MIRROR		= 0x2,	/* mirrored region */
	MEMBLOCK_NOMAP		= 0x4,	/* don't add to kernel direct mapping */
};

struct memblock_region {
	phys_addr_t base;
	phys_addr_t size;
	unsigned long flags;
	int nid;
};

struct memblock_type {
	unsigned long cnt;		/* number of regions */
	unsigned long max;		/* size of the allocated array */
	phys_addr_t total_size;		/* size of all regions */
	struct memblock_region *regions;
};

struct memblock {
	/* is bottom up direction? */
	bool bottom_up;
	phys_addr_t current_limit;
	struct memblock_type memory;
	struct memblock_type reserved;
};

/* Flags for memblock_alloc_base() amd __memblock_alloc_base() */
#define MEMBLOCK_ALLOC_ANYWHERE		(~(phys_addr_t)0)
#define MEMBLOCK_ALLOC_ACCESSIBLE	0

extern struct memblock memblock;
extern int memblock_debug;

void __next_mem_range(u64 *idx, int nid, unsigned long flags,
		      struct memblock_type *type_a,
		      struct memblock_type *type_b, phys_addr_t *out_start,
		      phys_addr_t *out_end, int *out_nid);

void __next_mem_range_rev(u64 *idx, int nid, unsigned long flags,
			  struct memblock_type *type_a,
			  struct memblock_type *type_b, phys_addr_t *out_start,
			  phys_addr_t *out_end, int *out_nid);

#define memblock_dbg(fmt, ...) \
	if (memblock_debug) printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)

#define for_each_memblock(memblock_type, region)					\
	for (region = memblock.memblock_type.regions;					\
	     region < (memblock.memblock_type.regions + memblock.memblock_type.cnt);	\
	     region++)

#define for_each_memblock_type(memblock_type, rgn)			\
	for (idx = 0, rgn = &memblock_type->regions[0];			\
	     idx < memblock_type->cnt;					\
	     idx++, rgn = &memblock_type->regions[idx])

/**
 * for_each_mem_range - iterate through memblock areas from type_a and not
 * included in type_b. Or just type_a if type_b is NULL.
 * @i: u64 used as loop variable
 * @type_a: ptr to memblock_type to iterate
 * @type_b: ptr to memblock_type which excludes from the iteration
 * @nid: node selector, %NUMA_NO_NODE for all nodes
 * @flags: pick from blocks based on memory attributes
 * @p_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @p_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @p_nid: ptr to int for nid of the range, can be %NULL
 */
#define for_each_mem_range(i, type_a, type_b, nid, flags,		\
			   p_start, p_end, p_nid)			\
	for (i = 0, __next_mem_range(&i, nid, flags, type_a, type_b,	\
				     p_start, p_end, p_nid);		\
	     i != (u64)ULLONG_MAX;					\
	     __next_mem_range(&i, nid, flags, type_a, type_b,		\
			      p_start, p_end, p_nid))

/**
 * for_each_mem_range_rev - reverse iterate through memblock areas from
 * type_a and not included in type_b. Or just type_a if type_b is NULL.
 * @i: u64 used as loop variable
 * @type_a: ptr to memblock_type to iterate
 * @type_b: ptr to memblock_type which excludes from the iteration
 * @nid: node selector, %NUMA_NO_NODE for all nodes
 * @flags: pick from blocks based on memory attributes
 * @p_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @p_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @p_nid: ptr to int for nid of the range, can be %NULL
 */
#define for_each_mem_range_rev(i, type_a, type_b, nid, flags,		\
			       p_start, p_end, p_nid)			\
	for (i = (u64)ULLONG_MAX,					\
		     __next_mem_range_rev(&i, nid, flags, type_a, type_b,\
					  p_start, p_end, p_nid);	\
	     i != (u64)ULLONG_MAX;					\
	     __next_mem_range_rev(&i, nid, flags, type_a, type_b,	\
				  p_start, p_end, p_nid))

/**
 * for_each_free_mem_range - iterate through free memblock areas
 * @i: u64 used as loop variable
 * @nid: node selector, %NUMA_NO_NODE for all nodes
 * @flags: pick from blocks based on memory attributes
 * @p_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @p_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @p_nid: ptr to int for nid of the range, can be %NULL
 *
 * Walks over free (memory && !reserved) areas of memblock.  Available as
 * soon as memblock is initialized.
 */
#define for_each_free_mem_range(i, nid, flags, p_start, p_end, p_nid)	\
	for_each_mem_range(i, &memblock.memory, &memblock.reserved,	\
			   nid, flags, p_start, p_end, p_nid)

/**
 * for_each_free_mem_range_reverse - rev-iterate through free memblock areas
 * @i: u64 used as loop variable
 * @nid: node selector, %NUMA_NO_NODE for all nodes
 * @flags: pick from blocks based on memory attributes
 * @p_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @p_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @p_nid: ptr to int for nid of the range, can be %NULL
 *
 * Walks over free (memory && !reserved) areas of memblock in reverse
 * order.  Available as soon as memblock is initialized.
 */
#define for_each_free_mem_range_reverse(i, nid, flags, p_start, p_end,	\
					p_nid)				\
	for_each_mem_range_rev(i, &memblock.memory, &memblock.reserved,	\
			       nid, flags, p_start, p_end, p_nid)

void __next_mem_pfn_range(int *idx, int nid, unsigned long *out_start_pfn,
			  unsigned long *out_end_pfn, int *out_nid);

/**
 * for_each_mem_pfn_range - early memory pfn range iterator
 * @i: an integer used as loop variable
 * @nid: node selector, %MAX_NUMNODES for all nodes
 * @p_start: ptr to ulong for start pfn of the range, can be %NULL
 * @p_end: ptr to ulong for end pfn of the range, can be %NULL
 * @p_nid: ptr to int for nid of the range, can be %NULL
 *
 * Walks over configured memory ranges.
 */
#define for_each_mem_pfn_range(i, nid, p_start, p_end, p_nid)		\
	for (i = -1, __next_mem_pfn_range(&i, nid, p_start, p_end, p_nid); \
	     i >= 0; __next_mem_pfn_range(&i, nid, p_start, p_end, p_nid))

phys_addr_t memblock_find_in_range_node(phys_addr_t size, phys_addr_t align,
					phys_addr_t start, phys_addr_t end,
					int nid, unsigned long flags);
phys_addr_t memblock_find_in_range(phys_addr_t start, phys_addr_t end,
				   phys_addr_t size, phys_addr_t align);
int memblock_add_node(phys_addr_t base, phys_addr_t size, int nid);
int memblock_add(phys_addr_t base, phys_addr_t size);
int memblock_remove(phys_addr_t base, phys_addr_t size);
int memblock_free(phys_addr_t base, phys_addr_t size);
int memblock_reserve(phys_addr_t base, phys_addr_t size);
void memblock_trim_memory(phys_addr_t align);

int memblock_is_region_memory(phys_addr_t base, phys_addr_t size);
bool memblock_is_region_reserved(phys_addr_t base, phys_addr_t size);
void memblock_trim_memory(phys_addr_t align);
int memblock_search_pfn_nid(unsigned long pfn, unsigned long *start_pfn, unsigned long *end_pfn);

void __memblock_dump_all(void);
static inline void memblock_dump_all(void)
{
	if (memblock_debug)
		__memblock_dump_all();
}

static inline bool memblock_bottom_up(void) { return false; }

bool __init memblock_overlaps_region(struct memblock_type *type,
				     phys_addr_t base, phys_addr_t size);

int __init memblock_set_node(phys_addr_t base, phys_addr_t size,
			     struct memblock_type *type, int nid);

phys_addr_t memblock_alloc_nid(phys_addr_t size, phys_addr_t align, int nid);
phys_addr_t memblock_alloc_try_nid(phys_addr_t size, phys_addr_t align, int nid);
phys_addr_t memblock_alloc(phys_addr_t size, phys_addr_t align);

phys_addr_t __init memblock_alloc_range(phys_addr_t size, phys_addr_t align,
					phys_addr_t start, phys_addr_t end,
					unsigned long flags);
phys_addr_t memblock_alloc_base(phys_addr_t size, phys_addr_t align,
				phys_addr_t max_addr);
phys_addr_t __memblock_alloc_base(phys_addr_t size, phys_addr_t align,
				  phys_addr_t max_addr);


#define BOOTMEM_ALLOC_ACCESSIBLE	0
#define BOOTMEM_ALLOC_ANYWHERE		(~(phys_addr_t)0)

void *memblock_virt_alloc_try_nid_nopanic(phys_addr_t size,
		phys_addr_t align, phys_addr_t min_addr,
		phys_addr_t max_addr, int nid);

static inline void * __init memblock_virt_alloc_node_nopanic(
						phys_addr_t size, int nid)
{
	return memblock_virt_alloc_try_nid_nopanic(size, 0, 0,
						    BOOTMEM_ALLOC_ACCESSIBLE,
						    nid);
}

static inline void *__init memblock_virt_alloc_nopanic(phys_addr_t size,
						       phys_addr_t align)
{
	return memblock_virt_alloc_try_nid_nopanic(size, align, 0,
						    BOOTMEM_ALLOC_ACCESSIBLE,
						    NUMA_NO_NODE);
}

static inline void * __init memblock_virt_alloc(phys_addr_t size,
						phys_addr_t align)
{
	return memblock_virt_alloc_try_nid_nopanic(size, align, 0,
					    BOOTMEM_ALLOC_ACCESSIBLE,
					    NUMA_NO_NODE);
}

void __memblock_free_early(phys_addr_t base, phys_addr_t size);

static inline void __init memblock_free_early(
					phys_addr_t base, phys_addr_t size)
{
	__memblock_free_early(base, size);
}


void __next_reserved_mem_region(u64 *idx, phys_addr_t *out_start,
				phys_addr_t *out_end);

/**
 * for_each_reserved_mem_region - iterate over all reserved memblock areas
 * @i: u64 used as loop variable
 * @p_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @p_end: ptr to phys_addr_t for end address of the range, can be %NULL
 *
 * Walks over reserved areas of memblock. Available as soon as memblock
 * is initialized.
 */
#define for_each_reserved_mem_region(i, p_start, p_end)			\
	for (i = 0UL, __next_reserved_mem_region(&i, p_start, p_end);	\
	     i != (u64)ULLONG_MAX;					\
	     __next_reserved_mem_region(&i, p_start, p_end))

unsigned long __init free_all_bootmem(void);

extern void *alloc_large_system_hash(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long low_limit,
				     unsigned long high_limit);

#endif /* _LEGO_MEMBLOCK_H_ */
