/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MM_H_
#define _LEGO_MM_H_

#include <asm/page.h>
#include <asm/pgtable.h>

#include <lego/pfn.h>
#include <lego/gfp.h>
#include <lego/atomic.h>
#include <lego/kernel.h>
#include <lego/mm_zone.h>
#include <lego/mm_types.h>
#include <lego/memory_model.h>
#include <lego/page-flags.h>
#include <lego/page-flags-layout.h>

/* Page flags: | [NODE] | ZONE | ... | FLAGS | */
#define NODES_PGOFF		((sizeof(unsigned long)*8) - NODES_WIDTH)
#define ZONES_PGOFF		(NODES_PGOFF - ZONES_WIDTH)

/*
 * Define the bit shifts to access each section.  For non-existent
 * sections we define the shift as 0; that plus a 0 mask ensures
 * the compiler will optimise away reference to them.
 */
#define NODES_PGSHIFT		(NODES_PGOFF * (NODES_WIDTH != 0))
#define ZONES_PGSHIFT		(ZONES_PGOFF * (ZONES_WIDTH != 0))

/* NODE:ZONE is used to ID a zone for the buddy allocator */
#define ZONEID_SHIFT		(NODES_SHIFT + ZONES_SHIFT)
#define ZONEID_PGOFF		((NODES_PGOFF < ZONES_PGOFF)? \
						NODES_PGOFF : ZONES_PGOFF)

#define ZONEID_PGSHIFT		(ZONEID_PGOFF * (ZONEID_SHIFT != 0))

#if NODES_WIDTH+ZONES_WIDTH > BITS_PER_LONG - NR_PAGEFLAGS
# error NODES_WIDTH+ZONES_WIDTH > BITS_PER_LONG - NR_PAGEFLAGS
#endif

#define NODES_MASK		((1UL << NODES_WIDTH) - 1)
#define ZONES_MASK		((1UL << ZONES_WIDTH) - 1)
#define ZONEID_MASK		((1UL << ZONEID_SHIFT) - 1)

static inline enum zone_type page_to_zonetype(const struct page *page)
{
	return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
}

/*
 * The identification function is mainly used by the buddy allocator for
 * determining if two pages could be buddies.
 *
 * We only guarantee that it will return the same value for two combinable
 * pages in a zone.
 */
static inline int page_to_zoneid(struct page *page)
{
	return (page->flags >> ZONEID_PGSHIFT) & ZONEID_MASK;
}

static inline int zone_to_nid(struct zone *zone)
{
#ifdef CONFIG_NUMA
	return zone->node;
#else
	return 0;
#endif
}

static inline int page_to_nid(const struct page *page)
{
	return (page->flags >> NODES_PGSHIFT) & NODES_MASK;
}

/* TODO */
#ifndef CONFIG_FLATMEM
#define pfn_to_nid(pfn)		(0)
#endif

static inline struct zone *page_zone(const struct page *page)
{
	enum zone_type type = page_to_zonetype(page);
	int nid = page_to_nid(page);

	return &NODE_DATA(nid)->node_zones[type];
}

static inline pg_data_t *page_pgdat(const struct page *page)
{
	return NODE_DATA(page_to_nid(page));
}

static inline void set_page_zone(struct page *page, enum zone_type zone)
{
	page->flags &= ~(ZONES_MASK << ZONES_PGSHIFT);
	page->flags |= (zone & ZONES_MASK) << ZONES_PGSHIFT;
}

static inline void set_page_node(struct page *page, unsigned long node)
{
	page->flags &= ~(NODES_MASK << NODES_PGSHIFT);
	page->flags |= (node & NODES_MASK) << NODES_PGSHIFT;
}

static inline void set_page_links(struct page *page, enum zone_type zone,
				  unsigned long node)
{
	set_page_zone(page, zone);
	set_page_node(page, node);
}

#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr)	ALIGN(addr, PAGE_SIZE)

/* highest direct mapped pfn */
extern unsigned long max_pfn_mapped;

/* highest pfn of this machine */
extern unsigned long max_pfn;

/* Defined in mm/page_alloc.c */
extern unsigned long totalram_pages;
extern unsigned long totalreserve_pages;

/* Defined in mm/init-mm.c */
extern struct mm_struct init_mm;

void __init free_area_init_nodes(unsigned long *max_zone_pfn);

void __init arch_zone_init(void);
void __init memory_init(void);

static inline int pfn_valid(unsigned long pfn)
{
	return pfn < max_pfn;
}

static inline void set_page_count(struct page *page, int v)
{
	atomic_set(&page->_refcount, v);
}

/*
 * Setup the page count before being freed into the page allocator for
 * the first time (boot or memory hotplug)
 */
static inline void init_page_count(struct page *page)
{
	set_page_count(page, 1);
}

/*
 * The atomic page->_mapcount, starts from -1: so that transitions
 * both from it and to it can be tracked, using atomic_inc_and_test
 * and atomic_add_negative(-1).
 */
static inline void page_mapcount_reset(struct page *page)
{
	atomic_set(&(page)->_mapcount, -1);
}

void reserve_bootmem_region(phys_addr_t start, phys_addr_t end);

void __free_pages_bootmem(struct page *page, unsigned long pfn,
			unsigned int order);

void __free_pages(struct page *page, unsigned int order);
void free_pages(unsigned long addr, unsigned int order);

#define __free_page(page) __free_pages((page), 0)
#define free_page(addr) free_pages((addr), 0)

struct page *alloc_pages(gfp_t gfp_mask, unsigned int order);

#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)

#endif /* _LEGO_MM_H_ */
