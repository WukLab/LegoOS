/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MEMBLOCK_H_
#define _LEGO_MEMBLOCK_H_

#include <lego/types.h>

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

#endif /* _LEGO_MEMBLOCK_H_ */
