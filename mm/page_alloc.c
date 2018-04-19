/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Physical page management:
 * 1) Boot-time initilization
 * 2) Runtime buddy allocator
 */

#include <lego/mm.h>
#include <lego/init.h>
#include <lego/numa.h>
#include <lego/sched.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/vmstat.h>
#include <lego/sysinfo.h>
#include <lego/nodemask.h>
#include <lego/memblock.h>
#include <lego/spinlock.h>

#include <asm/io.h>
#include <asm/page.h>
#include <asm/numa.h>

static unsigned long nr_kernel_pages;
static unsigned long nr_all_pages;
static unsigned long dma_reserve;

unsigned long totalram_pages __read_mostly;
unsigned long totalreserve_pages __read_mostly;

/* The highest pfn that mem_map is managing */
unsigned long highest_memmap_pfn __read_mostly;

/**
 * node_states - Array of node states.
 */
nodemask_t node_states[NR_NODE_STATES] __read_mostly = {
	[N_POSSIBLE] = NODE_MASK_ALL,
	[N_ONLINE] = { { [0] = 1UL } },
#ifndef CONFIG_NUMA
	[N_NORMAL_MEMORY] = { { [0] = 1UL } },
	[N_CPU] = { { [0] = 1UL } },
#endif
};

#if MAX_NUMNODES > 1
int nr_node_ids __read_mostly = MAX_NUMNODES;
int nr_online_nodes __read_mostly = 1;

void __init setup_nr_node_ids(void)
{
	unsigned int highest;

	highest = find_last_bit(node_possible_map.bits, MAX_NUMNODES);
	nr_node_ids = highest + 1;
}
#endif

static char * const zone_names[MAX_NR_ZONES] = {
#ifdef CONFIG_ZONE_DMA
	 "DMA",
#endif
#ifdef CONFIG_ZONE_DMA32
	 "DMA32",
#endif
	 "Normal",
	 "Movable",
};

static unsigned long arch_zone_lowest_possible_pfn[MAX_NR_ZONES];
static unsigned long arch_zone_highest_possible_pfn[MAX_NR_ZONES];

/* Encode everything about the page structure */
static void __init_single_page(struct page *page, unsigned long pfn,
				unsigned long zone, int nid)
{
	set_page_links(page, zone, nid, pfn);
	init_page_count(page);
	page_mapcount_reset(page);
	INIT_LIST_HEAD(&page->lru);
}

static void __init_single_pfn(unsigned long pfn, unsigned long zone,
			      int nid)
{
	return __init_single_page(pfn_to_page(pfn), pfn, zone, nid);
}

/**
 * get_pfn_range_for_nid - Return the start and end page frames for a node
 * @nid: The nid to return the range for. If MAX_NUMNODES, the min and max PFN are returned.
 * @start_pfn: Passed by reference. On return, it will have the node start_pfn.
 * @end_pfn: Passed by reference. On return, it will have the node end_pfn.
 *
 * It returns the start and end page frame of a node based on information
 * provided by memblock_set_node(). If called for a node
 * with no available memory, a warning is printed and the start and end
 * PFNs will be 0.
 */
void __init get_pfn_range_for_nid(unsigned int nid,
				  unsigned long *start_pfn,
				  unsigned long *end_pfn)
{
	unsigned long this_start_pfn, this_end_pfn;
	int i;

	*start_pfn = -1UL;
	*end_pfn = 0;

	for_each_mem_pfn_range(i, nid, &this_start_pfn, &this_end_pfn, NULL) {
		*start_pfn = min(*start_pfn, this_start_pfn);
		*end_pfn = max(*end_pfn, this_end_pfn);
	}

	if (*start_pfn == -1UL)
		*start_pfn = 0;
}

/*
 * Return the number of pages a zone spans in a node, including holes
 * present_pages = zone_spanned_pages_in_node() - zone_absent_pages_in_node()
 */
static unsigned long __init zone_spanned_pages_in_node(int nid,
					unsigned long zone_type,
					unsigned long node_start_pfn,
					unsigned long node_end_pfn,
					unsigned long *zone_start_pfn,
					unsigned long *zone_end_pfn,
					unsigned long *ignored)
{
	/* Get the start and end of the zone */
	*zone_start_pfn = arch_zone_lowest_possible_pfn[zone_type];
	*zone_end_pfn = arch_zone_highest_possible_pfn[zone_type];

	/* Check that this node has pages within the zone's required range */
	if (*zone_end_pfn < node_start_pfn || *zone_start_pfn > node_end_pfn)
		return 0;

	/* Move the zone boundaries inside the node if necessary */
	*zone_end_pfn = min(*zone_end_pfn, node_end_pfn);
	*zone_start_pfn = max(*zone_start_pfn, node_start_pfn);

	/* Return the spanned pages */
	return *zone_end_pfn - *zone_start_pfn;
}

/*
 * Return the number of holes in a range on a node. If nid is MAX_NUMNODES,
 * then all holes in the requested range will be accounted for.
 */
unsigned long __init __absent_pages_in_range(int nid,
				unsigned long range_start_pfn,
				unsigned long range_end_pfn)
{
	unsigned long nr_absent = range_end_pfn - range_start_pfn;
	unsigned long start_pfn, end_pfn;
	int i;

	for_each_mem_pfn_range(i, nid, &start_pfn, &end_pfn, NULL) {
		start_pfn = clamp(start_pfn, range_start_pfn, range_end_pfn);
		end_pfn = clamp(end_pfn, range_start_pfn, range_end_pfn);
		nr_absent -= end_pfn - start_pfn;
	}
	return nr_absent;
}

/**
 * absent_pages_in_range - Return number of page frames in holes within a range
 * @start_pfn: The start PFN to start searching for holes
 * @end_pfn: The end PFN to stop searching for holes
 *
 * It returns the number of pages frames in memory holes within a range.
 */
unsigned long __init absent_pages_in_range(unsigned long start_pfn,
					   unsigned long end_pfn)
{
	return __absent_pages_in_range(MAX_NUMNODES, start_pfn, end_pfn);
}

/* Return the number of page frames in holes in a zone on a node */
static unsigned long __init zone_absent_pages_in_node(int nid,
					unsigned long zone_type,
					unsigned long node_start_pfn,
					unsigned long node_end_pfn,
					unsigned long *ignored)
{
	unsigned long zone_low = arch_zone_lowest_possible_pfn[zone_type];
	unsigned long zone_high = arch_zone_highest_possible_pfn[zone_type];
	unsigned long zone_start_pfn, zone_end_pfn;
	unsigned long nr_absent;

	zone_start_pfn = clamp(node_start_pfn, zone_low, zone_high);
	zone_end_pfn = clamp(node_end_pfn, zone_low, zone_high);

	nr_absent = __absent_pages_in_range(nid, zone_start_pfn, zone_end_pfn);

	return nr_absent;
}

static void __init calculate_node_totalpages(struct pglist_data *pgdat,
					     unsigned long node_start_pfn,
					     unsigned long node_end_pfn,
					     unsigned long *zones_size,
					     unsigned long *zholes_size)
{
	unsigned long realtotalpages = 0, totalpages = 0;
	enum zone_type i;

	for (i = 0; i < MAX_NR_ZONES; i++) {
		struct zone *zone = pgdat->node_zones + i;
		unsigned long zone_start_pfn, zone_end_pfn;
		unsigned long size, real_size;

		size = zone_spanned_pages_in_node(pgdat->node_id, i,
						  node_start_pfn,
						  node_end_pfn,
						  &zone_start_pfn,
						  &zone_end_pfn,
						  zones_size);
		real_size = size - zone_absent_pages_in_node(pgdat->node_id, i,
						  node_start_pfn, node_end_pfn,
						  zholes_size);
		if (size)
			zone->zone_start_pfn = zone_start_pfn;
		else
			zone->zone_start_pfn = 0;
		zone->spanned_pages = size;
		zone->present_pages = real_size;

		totalpages += size;
		realtotalpages += real_size;
	}

	pgdat->node_spanned_pages = totalpages;
	pgdat->node_present_pages = realtotalpages;

	pr_debug("On node %d totalpages: %lu\n", pgdat->node_id, realtotalpages);
}

static unsigned long calc_memmap_size(unsigned long spanned_pages,
				      unsigned long present_pages)
{
	unsigned long pages = spanned_pages;

	/*
	 * Provide a more accurate estimation if there are holes within
	 * the zone and SPARSEMEM is in use. If there are holes within the
	 * zone, each populated memory region may cost us one or two extra
	 * memmap pages due to alignment because memmap pages for each
	 * populated regions may not naturally algined on page boundary.
	 * So the (present_pages >> 4) heuristic is a tradeoff for that.
	 */
	if (spanned_pages > present_pages + (present_pages >> 4) &&
	    IS_ENABLED(CONFIG_SPARSEMEM))
		pages = present_pages;

	return PAGE_ALIGN(pages * sizeof(struct page)) >> PAGE_SHIFT;
}

/*
 * Initially all pages are reserved - free ones are freed
 * up by free_all_bootmem() once the early boot process is
 * done. Non-atomic initialization, single-pass.
 */
static void __init zone_init_mem_map(unsigned long size, int nid,
				     unsigned long zone, unsigned long start_pfn)
{
	unsigned long end_pfn = start_pfn + size;
	unsigned long pfn;

	if (highest_memmap_pfn < end_pfn - 1)
		highest_memmap_pfn = end_pfn - 1;

	for (pfn = start_pfn; pfn < end_pfn; pfn++) {
		/*
		 * FAT NOTE:
		 * There can be holes inside zone range.
		 * And for sparsemem, the mem_section maybe unused
		 * Hence we must use pfn_valid() to bail out
		 */
		if (!pfn_valid(pfn))
			continue;
		__init_single_pfn(pfn, zone, nid);
	}
}

static void zone_init_free_lists(struct zone *zone)
{
	unsigned int order;
	for_each_order(order) {
		INIT_LIST_HEAD(&zone->free_area[order].free_list);
		zone->free_area[order].nr_free = 0;
	}
}

/* TODO */
static void zone_pcp_init(struct zone *zone)
{

}

/*
 * Set up the zone data structures:
 *   - mark all pages reserved
 *   - mark all memory queues empty
 *   - clear the memory bitmaps
 *
 * NOTE: pgdat should get zeroed by caller.
 */
static void __init free_area_init_core(pg_data_t *pgdat)
{
	int j;
	int nid = pgdat->node_id;

	for (j = 0; j < MAX_NR_ZONES; j++) {
		struct zone *zone = pgdat->node_zones + j;
		unsigned long size, realsize, freesize, memmap_pages;

		size = zone->spanned_pages;
		realsize = freesize = zone->present_pages;

		/*
		 * Adjust freesize so that it accounts for how much memory
		 * is used by this zone for memmap. This affects the watermark
		 * and per-cpu initialisations
		 */
		memmap_pages = calc_memmap_size(size, realsize);
		if (freesize >= memmap_pages) {
			freesize -= memmap_pages;
			if (memmap_pages)
				printk(KERN_DEBUG
				       "  %s zone: %lu pages used in memmap\n",
				       zone_names[j], memmap_pages);
		} else
			pr_warn("  %s zone: %lu pages exceeds freesize %lu\n",
				zone_names[j], memmap_pages, freesize);

		/* Account for reserved pages */
		if (j == 0 && freesize > dma_reserve) {
			freesize -= dma_reserve;
			printk(KERN_DEBUG "  %s zone: %lu pages reserved\n",
					zone_names[0], dma_reserve);
		}

		nr_kernel_pages += freesize;
		nr_all_pages += freesize;

		zone->managed_pages = freesize;

#ifdef CONFIG_NUMA
		zone->node = nid;
#endif
		zone->name = zone_names[j];
		zone->zone_pgdat = pgdat;
		spin_lock_init(&zone->lock);
		zone_pcp_init(zone);

		if (!size)
			continue;

		zone_init_free_lists(zone);
		zone_init_mem_map(size, nid, j, zone->zone_start_pfn);
	}
}

static void alloc_node_mem_map(struct pglist_data *pgdat, unsigned long *mem_map_size)
{
	unsigned long __maybe_unused start = 0;
	unsigned long __maybe_unused offset = 0;
	unsigned long __maybe_unused size;
	unsigned long __maybe_unused end;
	struct page __maybe_unused *map;

	/* Skip empty nodes */
	if (!pgdat->node_spanned_pages)
		return;

#ifndef CONFIG_SPARSEMEM
	start = pgdat->node_start_pfn & ~(MAX_ORDER_NR_PAGES - 1);
	offset = pgdat->node_start_pfn - start;

	/*
	 * The zone's endpoints aren't required to be MAX_ORDER
	 * aligned but the node_mem_map endpoints must be in order
	 * for the buddy allocator to function correctly.
	 */
	end = pgdat_end_pfn(pgdat);
	end = ALIGN(end, MAX_ORDER_NR_PAGES);
	size =  (end - start) * sizeof(struct page);
	*mem_map_size = size;
	map = memblock_virt_alloc_node_nopanic(size, pgdat->node_id);
	pgdat->node_mem_map = map + offset;

#ifndef CONFIG_NEED_MULTIPLE_NODES
	/*
	 * With no DISCONTIG, the global mem_map is just set as node 0's
	 */
	if (pgdat == NODE_DATA(0)) {
		mem_map = NODE_DATA(0)->node_mem_map;
#if defined(CONFIG_HAVE_MEMBLOCK_NODE_MAP) || defined(CONFIG_FLATMEM)
		if (page_to_pfn(mem_map) != pgdat->node_start_pfn)
			mem_map -= offset;
#endif
	}
#endif /* CONFIG_NEED_MULTIPLE_NODES */
#endif /* CONFIG_SPARSEMEM */
}

void __init free_area_init_node(int nid, unsigned long *zones_size,
				unsigned long node_start_pfn,
				unsigned long *zholes_size)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	unsigned long start_pfn = 0;
	unsigned long end_pfn = 0;
	unsigned long mem_map_size = 0;

	pgdat->node_id = nid;
	pgdat->node_start_pfn = node_start_pfn;

	get_pfn_range_for_nid(nid, &start_pfn, &end_pfn);

	pr_info("Initmem setup node %d [mem %#018Lx-%#018Lx]\n", nid,
		(u64)start_pfn << PAGE_SHIFT,
		end_pfn ? ((u64)end_pfn << PAGE_SHIFT) - 1 : 0);

	calculate_node_totalpages(pgdat, start_pfn, end_pfn,
				  zones_size, zholes_size);

	alloc_node_mem_map(pgdat, &mem_map_size);
#ifndef CONFIG_SPARSEMEM
	pr_debug("%s: node %d, pgdat %#08lx, node_mem_map %#08lx - %#08lx\n",
		 __func__, nid, (unsigned long)pgdat,
		 (unsigned long)pgdat->node_mem_map,
		 (unsigned long)pgdat->node_mem_map + mem_map_size);
#endif
	free_area_init_core(pgdat);
}

/* Find the lowest pfn for a node */
static unsigned long __init find_min_pfn_for_node(int nid)
{
	unsigned long min_pfn = ULONG_MAX;
	unsigned long start_pfn;
	int i;

	for_each_mem_pfn_range(i, nid, &start_pfn, NULL, NULL)
		min_pfn = min(min_pfn, start_pfn);

	if (min_pfn == ULONG_MAX) {
		pr_warn("Could not find start_pfn for node %d\n", nid);
		return 0;
	}

	return min_pfn;
}

/**
 * find_min_pfn_with_active_regions - Find the minimum PFN registered
 *
 * It returns the minimum PFN based on information provided via
 * memblock_set_node().
 */
unsigned long __init find_min_pfn_with_active_regions(void)
{
	return find_min_pfn_for_node(MAX_NUMNODES);
}

/**
 * free_area_init_nodes - Initialise all pg_data_t and zone data
 * @max_zone_pfn: an array of max PFNs for each zone
 *
 * This will call free_area_init_node() for each active node in the system.
 * Using the page ranges provided by memblock_set_node(), the size of each
 * zone in each node and their holes is calculated. If the maximum PFN
 * between two adjacent zones match, it is assumed that the zone is empty.
 * For example, if arch_max_dma_pfn == arch_max_dma32_pfn, it is assumed
 * that arch_max_dma32_pfn has no pages. It is also assumed that a zone
 * starts where the previous one ended. For example, ZONE_DMA32 starts
 * at arch_max_dma_pfn.
 */
void __init free_area_init_nodes(unsigned long *max_zone_pfn)
{
	unsigned long start_pfn, end_pfn;
	int i, nid;

	/* Record where the zone boundaries are */
	memset(arch_zone_lowest_possible_pfn, 0,
				sizeof(arch_zone_lowest_possible_pfn));
	memset(arch_zone_highest_possible_pfn, 0,
				sizeof(arch_zone_highest_possible_pfn));

	start_pfn = find_min_pfn_with_active_regions();

	for (i = 0; i < MAX_NR_ZONES; i++) {
		end_pfn = max(max_zone_pfn[i], start_pfn);
		arch_zone_lowest_possible_pfn[i] = start_pfn;
		arch_zone_highest_possible_pfn[i] = end_pfn;

		start_pfn = end_pfn;
	}

	/* Print out the zone ranges */
	pr_info("Zone ranges:\n");
	for (i = 0; i < MAX_NR_ZONES; i++) {
		pr_info("  %-8s ", zone_names[i]);
		if (arch_zone_lowest_possible_pfn[i] ==
				arch_zone_highest_possible_pfn[i])
			pr_cont("empty\n");
		else
			pr_cont("[mem %#018Lx-%#018Lx]\n",
				(u64)arch_zone_lowest_possible_pfn[i]
					<< PAGE_SHIFT,
				((u64)arch_zone_highest_possible_pfn[i]
					<< PAGE_SHIFT) - 1);
	}

	/* Print out the early node map */
	pr_info("Early memory node ranges\n");
	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid)
		pr_info("  node %3d: [mem %#018Lx-%#018Lx]\n", nid,
			(u64)start_pfn << PAGE_SHIFT,
			((u64)end_pfn << PAGE_SHIFT) - 1);

	for_each_online_node(nid) {
		pg_data_t *pgdat = NODE_DATA(nid);
		free_area_init_node(nid, NULL,
				find_min_pfn_for_node(nid), NULL);

		/* Any memory on that node */
		if (pgdat->node_present_pages)
			node_set_state(nid, N_NORMAL_MEMORY);
	}
}

/*
 * Locate the struct page for both the matching buddy in our
 * pair (buddy1) and the combined O(n+1) page they form (page).
 *
 * 1) Any buddy B1 will have an order O twin B2 which satisfies
 * the following equation:
 *     B2 = B1 ^ (1 << O)
 * For example, if the starting buddy (buddy2) is #8 its order
 * 1 buddy is #10:
 *     B2 = 8 ^ (1 << 1) = 8 ^ 2 = 10
 *
 * 2) Any buddy B will have an order O+1 parent P which
 * satisfies the following equation:
 *     P = B & ~(1 << O)
 *
 * Assumption: *_mem_map is contiguous at least up to MAX_ORDER
 */
static inline unsigned long
__find_buddy_index(unsigned long page_idx, unsigned int order)
{
	return page_idx ^ (1 << order);
}

static inline void set_page_order(struct page *page, unsigned int order)
{
	set_page_private(page, order);
	__SetPageBuddy(page);
}

static inline void rmv_page_order(struct page *page)
{
	__ClearPageBuddy(page);
	set_page_private(page, 0);
}

/*
 * This function checks whether a page is free && is the buddy
 * we can do coalesce a page and its buddy if
 * (a) the buddy is not in a hole &&
 * (b) the buddy is in the buddy system &&
 * (c) a page and its buddy have the same order &&
 * (d) a page and its buddy are in the same zone.
 *
 * For recording whether a page is in the buddy system, we set ->_mapcount
 * PAGE_BUDDY_MAPCOUNT_VALUE.
 * Setting, clearing, and testing _mapcount PAGE_BUDDY_MAPCOUNT_VALUE is
 * serialized by zone->lock.
 *
 * For recording page's order, we use page_private(page).
 */
static inline int page_is_buddy(struct page *page, struct page *buddy,
							unsigned int order)
{
	if (PageBuddy(buddy) && page_order(buddy) == order) {
		/*
		 * zone check is done late to avoid uselessly
		 * calculating zone/node ids for pages that could
		 * never merge.
		 */
		if (page_zone_id(page) != page_zone_id(buddy))
			return 0;

		VM_BUG_ON_PAGE(page_ref_count(buddy) != 0, buddy);

		return 1;
	}
	return 0;
}

static void
__free_one_page(struct page *page, unsigned long pfn, struct zone *zone,
		unsigned int order)
{
	unsigned long page_idx;
	unsigned long combined_idx;
	unsigned long buddy_idx;
	struct page *buddy;

	__mod_zone_page_state(zone, NR_FREE_PAGES, 1 << order);

	page_idx = pfn & ((1 << MAX_ORDER) - 1);

	VM_BUG_ON_PAGE(page_idx & ((1 << order) - 1), page);

	while (order < MAX_ORDER - 1) {
		buddy_idx = __find_buddy_index(page_idx, order);
		buddy = page + (buddy_idx - page_idx);
		if (!page_is_buddy(page, buddy, order))
			goto done_merging;

		list_del(&buddy->lru);
		zone->free_area[order].nr_free--;
		rmv_page_order(buddy);

		combined_idx = buddy_idx & page_idx;
		page = page + (combined_idx - page_idx);
		page_idx = combined_idx;
		order++;
	}

done_merging:
	set_page_order(page, order);

	list_add(&page->lru, &zone->free_area[order].free_list);
	zone->free_area[order].nr_free++;
}

static void free_one_page(struct zone *zone,
			struct page *page, unsigned long pfn,
			unsigned int order)
{
	spin_lock(&zone->lock);
	__free_one_page(page, pfn, zone, order);
	spin_unlock(&zone->lock);
}

static void bad_page(struct page *page, const char *reason,
		unsigned long bad_flags)
{
	pr_alert("BUG: Bad page state in process %s  pfn:%05lx\n",
		current->comm, page_to_pfn(page));

	dump_page(page, reason);

	bad_flags &= page->flags;
	if (bad_flags)
		pr_alert("bad because of flags: %#lx(%pGp)\n",
						bad_flags, &bad_flags);
	dump_stack();

	/* Leave bad fields for debug, except PageBuddy could make trouble */
	/* remove PageBuddy */
	page_mapcount_reset(page);
}

static __always_inline bool
page_expected_state(struct page *page, unsigned long check_flags)
{
	if (unlikely(atomic_read(&page->_mapcount) != -1))
		return false;

	if (unlikely(page_ref_count(page) != 0))
		return false;

	if (unlikely(page->flags & check_flags))
		return false;

	return true;
}

static void free_pages_check_bad(struct page *page)
{
	const char *bad_reason;
	unsigned long bad_flags;

	bad_reason = NULL;
	bad_flags = 0;

	if (unlikely(atomic_read(&page->_mapcount) != -1))
		bad_reason = "nonzero _mapcount";
	if (unlikely(page_ref_count(page) != 0))
		bad_reason = "nonzero _refcount";
	if (unlikely(page->flags & PAGE_FLAGS_CHECK_AT_FREE)) {
		bad_reason = "PAGE_FLAGS_CHECK_AT_FREE flag(s) set";
		bad_flags = PAGE_FLAGS_CHECK_AT_FREE;
	}
	bad_page(page, bad_reason, bad_flags);
}

static __always_inline int
free_pages_check(struct page *page)
{
	if (likely(page_expected_state(page, PAGE_FLAGS_CHECK_AT_FREE)))
		return 0;

	/* Something has gone sideways, find it */
	free_pages_check_bad(page);
	return 1;
}

/*
 * Someone is going to free a page.
 * Do some *necessary* checking before letting go.
 */
static __always_inline bool
free_pages_prepare(struct page *page, unsigned int order, bool check_free)
{
	int bad = 0;

	if (unlikely(order)) {
		int i;

		for (i = 1; i < (1 << order); i++) {
			if (unlikely(free_pages_check(page + i))) {
				bad++;
				continue;
			}
			(page + i)->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
		}
	}

	if (check_free)
		bad += free_pages_check(page);

	if (bad)
		return false;

	page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;

	return true;
}

/*
 * Ok or not ok, this is a question.
 *
 * If we have some problems about the going-to-freed page,
 * then we will dump page, then complain about it and do nothing.
 */
static void __free_pages_ok(struct page *page, unsigned int order)
{
	unsigned long flags;
	unsigned long pfn = page_to_pfn(page);

	if (!free_pages_prepare(page, order, true))
		return;

	local_irq_save(flags);
	free_one_page(page_zone(page), page, pfn, order);
	local_irq_restore(flags);
}

void __free_pages_boot(struct page *page, unsigned int order)
{
	if (put_page_testzero(page)) {
		__free_pages_ok(page, order);
	}
}

void __free_pages(struct page *page, unsigned int order)
{
#ifndef CONFIG_DEBUG_KMALLOC_USE_BUDDY
	if (put_page_testzero(page)) {
		__free_pages_ok(page, order);
	}
#endif
}

void free_pages(unsigned long addr, unsigned int order)
{
#ifndef CONFIG_DEBUG_KMALLOC_USE_BUDDY
	if (addr != 0) {
		VM_BUG_ON(!virt_addr_valid(addr));
		__free_pages(virt_to_page((void *)addr), order);
	}
#endif
}

static __always_inline void __clear_page(void *page)
{
	/* XXX: Trace this if necessary */
	memset(page, 0, PAGE_SIZE);
}

static void prep_new_page(struct page *page, unsigned int order, gfp_t gfp_flags)
{
	int i;

	if (gfp_flags & __GFP_ZERO) {
		for (i = 0; i < (1 << order); i++)
			__clear_page(page_to_virt(page + i));
	}

	set_page_private(page, 0);
	set_page_refcounted(page);
}

static inline void expand(struct zone *zone, struct page *page,
	int low, int high, struct free_area *area)
{
	unsigned long size = 1 << high;

	while (high > low) {
		area--;
		high--;
		size >>= 1;

		list_add(&page[size].lru, &area->free_list);
		area->nr_free++;
		set_page_order(&page[size], high);
	}
}

/* Remove an element from the buddy allocator from the fallback list */
static inline struct page *
__rmqueue_fallback(struct zone *zone, unsigned int order)
{
	return NULL;
}

/*
 * Go through the free lists for the given migratetype and remove
 * the smallest available page from the freelists
 */
static inline
struct page *__rmqueue_smallest(struct zone *zone, unsigned int order)
{
	unsigned int current_order;
	struct free_area *area;
	struct page *page;

	/* Find a page of the appropriate size in the preferred list */
	for (current_order = order; current_order < MAX_ORDER; ++current_order) {
		area = &(zone->free_area[current_order]);
		page = list_first_entry_or_null(&area->free_list, struct page, lru);
		if (!page)
			continue;
		list_del(&page->lru);
		rmv_page_order(page);
		area->nr_free--;
		expand(zone, page, order, current_order, area);
		return page;
	}

	return NULL;
}

/*
 * Do the hard work of removing an element from the buddy allocator.
 * Call me with the zone->lock already held.
 */
static inline struct page *__rmqueue(struct zone *zone, unsigned int order)
{
	struct page *page;
	
	page = __rmqueue_smallest(zone, order);
	if (unlikely(!page))
		page = __rmqueue_fallback(zone, order);
	return page;
}

static inline
struct page *buffered_rmqueue(struct zone *zone, unsigned int order,
			      gfp_t gfp_flags)
{
	unsigned long flags;
	struct page *page;

	/*
	 * We most definitely don't want callers attempting to
	 * allocate greater than order-1 page units with __GFP_NOFAIL.
	 */
	WARN_ON_ONCE((gfp_flags & __GFP_NOFAIL) && (order > 1));

	spin_lock_irqsave(&zone->lock, flags);
	page = __rmqueue(zone, order);
	spin_unlock(&zone->lock);
	if (!page)
		goto failed;

	__mod_zone_page_state(zone, NR_FREE_PAGES, -(1<< order));
	local_irq_restore(flags);
	return page;

failed:
	local_irq_restore(flags);
	return NULL;
}

static struct page *
get_page_from_freelist(gfp_t gfp_mask, unsigned int order,
		struct zonelist *zonelist, nodemask_t *nodemask)
{
	struct zone *zone;
	struct zoneref *z;
	enum zone_type high_zoneidx;

	/*
	 * GFP_DMA and GFP_DMA32 matter here
	 *
	 * Given these zone modifiers, the high_zoneidx will be set to a small
	 * value so the normal memory is skipped below to allocate from ZONE_DMA
	 * or ZONE_DMA32 first.
	 */
	high_zoneidx = gfp_zone(gfp_mask);

	for_each_zone_zonelist_nodemask(zone, z, zonelist, high_zoneidx, nodemask) {
		struct page *page;

		page = buffered_rmqueue(zone, order, gfp_mask);
		if (page) {
			prep_new_page(page, order, gfp_mask);
			return page;
		}
	}
	return NULL;
}

/*
 * The core of zoned buddy allocator..
 */
struct page *
__alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order,
		       struct zonelist *zonelist, nodemask_t *nodemask)
{
	struct page *page;

#ifdef CONFIG_DEBUG_BUDDY_FORCE_GFP_ZERO
	gfp_mask |= __GFP_ZERO;
#endif

	/*
	 * Check the zones suitable for the gfp_mask contain at least one
	 * valid zone. It's possible to have an empty zonelist as a result
	 * of __GFP_THISNODE and a memoryless node
	 */
	if (unlikely(!zonelist->_zonerefs->zone))
		return NULL;

	page = get_page_from_freelist(gfp_mask, order, zonelist, nodemask);
	if (unlikely(!page && order < MAX_ORDER)) {
		struct manager_sysinfo i;

		manager_meminfo(&i);
		panic("Out of Memory: free: %#lx\n", i.freeram);
	}
	return page;
}

static void __init __free_pages_boot_core(struct page *page, unsigned int order)
{
	unsigned int i, nr_pages = 1 << order;
	struct page *p = page;

	/* Cleanup */
	for (i = 0; i < nr_pages; i++, p++) {
		__ClearPageReserved(p);
		set_page_count(p, 0);
	}

	page_zone(page)->managed_pages += nr_pages;
	set_page_refcounted(page);
	__free_pages_boot(page, order);
}

/*
 * Initialised pages do not have PageReserved set. This function is
 * called for each range allocated by the bootmem allocator and
 * marks the pages PageReserved. The remaining valid pages are later
 * sent to the buddy page allocator.
 */
void __init reserve_bootmem_region(phys_addr_t start, phys_addr_t end)
{
	unsigned long start_pfn = PFN_DOWN(start);
	unsigned long end_pfn = PFN_UP(end);

	for (; start_pfn < end_pfn; start_pfn++) {
		if (pfn_valid(start_pfn)) {
			struct page *page = pfn_to_page(start_pfn);

			SetPageReserved(page);
		}
	}
}

/* Called to free memblock into buddy allocator */
void __init __free_pages_bootmem(struct page *page, unsigned long pfn,
				unsigned int order)
{
	return __free_pages_boot_core(page, order);
}

static void zoneref_set_zone(struct zone *zone, struct zoneref *zoneref)
{
	zoneref->zone = zone;
	zoneref->zone_idx = zone_idx(zone);
}

/*
 * Builds allocation fallback zone lists.
 *
 * Add all populated zones of a node to the zonelist.
 */
static int build_zonelists_node(pg_data_t *pgdat, struct zonelist *zonelist,
				int nr_zones)
{
	struct zone *zone;
	enum zone_type zone_type = MAX_NR_ZONES;

	/*
	 * Building from descending order
	 * So ZONE_NORMAL > ZONE_DMA in zonelist
	 */
	do {
		zone_type--;
		zone = pgdat->node_zones + zone_type;
		if (managed_zone(zone)) {
			zoneref_set_zone(zone,
				&zonelist->_zonerefs[nr_zones++]);
		}
	} while (zone_type);

	return nr_zones;
}

/*
 * zonelist_order:
 * 0 = automatic detection of better ordering.
 * 1 = order by ([node] distance, -zonetype)
 * 2 = order by (-zonetype, [node] distance)
 *
 * If not NUMA, ZONELIST_ORDER_ZONE and ZONELIST_ORDER_NODE will create
 * the same zonelist. So only NUMA can configure this param.
 */
#define ZONELIST_ORDER_DEFAULT  0
#define ZONELIST_ORDER_NODE     1
#define ZONELIST_ORDER_ZONE     2

/* zonelist order in the kernel.
 * set_zonelist_order() will set this to NODE or ZONE.
 */
static int current_zonelist_order = ZONELIST_ORDER_DEFAULT;
static char zonelist_order_name[3][8] = {"Default", "Node", "Zone"};

#ifdef CONFIG_NUMA
/* The value user specified ....changed by config */
static int user_zonelist_order = ZONELIST_ORDER_DEFAULT;

/*
 * Interface for configure zonelist ordering.
 * command line option "numa_zonelist_order"
 *	= "[dD]efault	- default, automatic configuration.
 *	= "[nN]ode 	- order by node locality, then by zone within node
 *	= "[zZ]one      - order by zone, then by locality within zone
 */
static int __parse_numa_zonelist_order(char *s)
{
	if (*s == 'd' || *s == 'D') {
		user_zonelist_order = ZONELIST_ORDER_DEFAULT;
	} else if (*s == 'n' || *s == 'N') {
		user_zonelist_order = ZONELIST_ORDER_NODE;
	} else if (*s == 'z' || *s == 'Z') {
		user_zonelist_order = ZONELIST_ORDER_ZONE;
	} else {
		pr_warn("Ignoring invalid numa_zonelist_order value:  %s\n", s);
		return -EINVAL;
	}
	return 0;
}

static __init int setup_numa_zonelist_order(char *s)
{
	int ret;

	if (!s)
		return 0;

	ret = __parse_numa_zonelist_order(s);
	return ret;
}
__setup("numa_zonelist_order", setup_numa_zonelist_order);

#define MAX_NODE_LOAD (nr_online_nodes)
static int node_load[MAX_NUMNODES];

#define PENALTY_FOR_NODE_WITH_CPUS	(1)

/**
 * find_next_best_node - find the next node that should appear in a given node's fallback list
 * @node: node whose fallback list we're appending
 * @used_node_mask: nodemask_t of already used nodes
 *
 * We use a number of factors to determine which is the next node that should
 * appear on a given node's fallback list.  The node should not have appeared
 * already in @node's fallback list, and it should be the next closest node
 * according to the distance array (which contains arbitrary distance values
 * from each node to each node in the system), and should also prefer nodes
 * with no CPUs, since presumably they'll have very little allocation pressure
 * on them otherwise.
 * It returns -1 if no node is found.
 */
static int find_next_best_node(int node, nodemask_t *used_node_mask)
{
	int n, val;
	int min_val = INT_MAX;
	int best_node = NUMA_NO_NODE;
	const struct cpumask *tmp = cpumask_of_node(0);

	/* Use the local node if we haven't already */
	if (!node_isset(node, *used_node_mask)) {
		node_set(node, *used_node_mask);
		return node;
	}

	for_each_node_state(n, N_NORMAL_MEMORY) {

		/* Don't want a node to appear more than once */
		if (node_isset(n, *used_node_mask))
			continue;

		/* Use the distance array to find the distance */
		val = node_distance(node, n);

		/* Penalize nodes under us ("prefer the next node") */
		val += (n < node);

		/* Give preference to headless and unused nodes */
		tmp = cpumask_of_node(n);
		if (!cpumask_empty(tmp))
			val += PENALTY_FOR_NODE_WITH_CPUS;

		/* Slight preference for less loaded node */
		val *= (MAX_NODE_LOAD*MAX_NUMNODES);
		val += node_load[n];

		if (val < min_val) {
			min_val = val;
			best_node = n;
		}
	}

	if (best_node >= 0)
		node_set(best_node, *used_node_mask);

	return best_node;
}

/*
 * Build zonelists ordered by node and zones within node.
 * This results in maximum locality--normal zone overflows into local
 * DMA zone, if any--but risks exhausting DMA zone.
 */
static void build_zonelists_in_node_order(pg_data_t *pgdat, int node)
{
	int j;
	struct zonelist *zonelist;

	zonelist = &pgdat->node_zonelists[ZONELIST_FALLBACK];
	for (j = 0; zonelist->_zonerefs[j].zone != NULL; j++)
		;

	/*
	 * All @node's zones into @pgdat's zonelist
	 * That is why we call it is node order.
	 */
	j = build_zonelists_node(NODE_DATA(node), zonelist, j);
	zonelist->_zonerefs[j].zone = NULL;
	zonelist->_zonerefs[j].zone_idx = 0;
}

/*
 * Build GFP_THISNODE zonelists
 */
static void build_thisnode_zonelists(pg_data_t *pgdat)
{
	int j;
	struct zonelist *zonelist;

	zonelist = &pgdat->node_zonelists[ZONELIST_NOFALLBACK];
	j = build_zonelists_node(pgdat, zonelist, 0);
	zonelist->_zonerefs[j].zone = NULL;
	zonelist->_zonerefs[j].zone_idx = 0;
}

/*
 * Build zonelists ordered by zone and nodes within zones.
 * This results in conserving DMA zone[s] until all Normal memory is
 * exhausted, but results in overflowing to remote node while memory
 * may still exist in local DMA zone.
 */
static int node_order[MAX_NUMNODES];

static void build_zonelists_in_zone_order(pg_data_t *pgdat, int nr_nodes)
{
	int pos, j, node;
	int zone_type;		/* needs to be signed */
	struct zone *z;
	struct zonelist *zonelist;

	zonelist = &pgdat->node_zonelists[ZONELIST_FALLBACK];
	pos = 0;
	for (zone_type = MAX_NR_ZONES - 1; zone_type >= 0; zone_type--) {
		for (j = 0; j < nr_nodes; j++) {
			node = node_order[j];
			z = &NODE_DATA(node)->node_zones[zone_type];
			if (managed_zone(z)) {
				zoneref_set_zone(z,
					&zonelist->_zonerefs[pos++]);
			}
		}
	}
	zonelist->_zonerefs[pos].zone = NULL;
	zonelist->_zonerefs[pos].zone_idx = 0;
}

#if defined(CONFIG_64BIT)
/*
 * Devices that require DMA32/DMA are relatively rare and do not justify a
 * penalty to every machine in case the specialised case applies. Default
 * to Node-ordering on 64-bit NUMA machines
 */
static int default_zonelist_order(void)
{
	return ZONELIST_ORDER_NODE;
}
#else
/*
 * On 32-bit, the Normal zone needs to be preserved for allocations accessible
 * by the kernel. If processes running on node 0 deplete the low memory zone
 * then reclaim will occur more frequency increasing stalls and potentially
 * be easier to OOM if a large percentage of the zone is under writeback or
 * dirty. The problem is significantly worse if CONFIG_HIGHPTE is not set.
 * Hence, default to zone ordering on 32-bit.
 */
static int default_zonelist_order(void)
{
	return ZONELIST_ORDER_ZONE;
}
#endif /* CONFIG_64BIT */

static void set_zonelist_order(void)
{
	if (user_zonelist_order == ZONELIST_ORDER_DEFAULT)
		current_zonelist_order = default_zonelist_order();
	else
		current_zonelist_order = user_zonelist_order;
}

static void build_zonelists(pg_data_t *pgdat)
{
	int i, node, load;
	nodemask_t used_mask;
	int local_node, prev_node;
	struct zonelist *zonelist;
	unsigned int order = current_zonelist_order;

	/* initialize zonelists */
	for (i = 0; i < MAX_ZONELISTS; i++) {
		zonelist = pgdat->node_zonelists + i;
		zonelist->_zonerefs[0].zone = NULL;
		zonelist->_zonerefs[0].zone_idx = 0;
	}

	/* NUMA-aware ordering of nodes */
	local_node = pgdat->node_id;
	load = nr_online_nodes;
	prev_node = local_node;
	nodes_clear(used_mask);

	memset(node_order, 0, sizeof(node_order));
	i = 0;

	while ((node = find_next_best_node(local_node, &used_mask)) >= 0) {
		/*
		 * We don't want to pressure a particular node.
		 * So adding penalty to the first node in same
		 * distance group to make it round-robin.
		 */
		if (node_distance(local_node, node) !=
		    node_distance(local_node, prev_node))
			node_load[node] = load;

		prev_node = node;
		load--;
		if (order == ZONELIST_ORDER_NODE)
			build_zonelists_in_node_order(pgdat, node);
		else
			node_order[i++] = node;	/* remember order */
	}

	if (order == ZONELIST_ORDER_ZONE) {
		/* calculate node order -- i.e., DMA last! */
		build_zonelists_in_zone_order(pgdat, i);
	}

	build_thisnode_zonelists(pgdat);
}

#else /* CONFIG_NUMA */

static void build_zonelists(pg_data_t *pgdat)
{
	int node, local_node;
	enum zone_type j;
	struct zonelist *zonelist;

	local_node = pgdat->node_id;

	zonelist = &pgdat->node_zonelists[ZONELIST_FALLBACK];
	j = build_zonelists_node(pgdat, zonelist, 0);

	/*
	 * Now we build the zonelist so that it contains the zones
	 * of all the other nodes.
	 * We don't want to pressure a particular node, so when
	 * building the zones for node N, we make sure that the
	 * zones coming right after the local ones are those from
	 * node N+1 (modulo N)
	 */
	for (node = local_node + 1; node < MAX_NUMNODES; node++) {
		if (!node_online(node))
			continue;
		j = build_zonelists_node(NODE_DATA(node), zonelist, j);
	}
	for (node = 0; node < local_node; node++) {
		if (!node_online(node))
			continue;
		j = build_zonelists_node(NODE_DATA(node), zonelist, j);
	}

	zonelist->_zonerefs[j].zone = NULL;
	zonelist->_zonerefs[j].zone_idx = 0;
}

static void set_zonelist_order(void)
{
	current_zonelist_order = ZONELIST_ORDER_ZONE;
}

#endif /* CONFIG_NUMA */

static void __init build_all_zonelists(void)
{
	int nid;

	set_zonelist_order();
	pr_debug("zonelist_order: %s\n", zonelist_order_name[current_zonelist_order]);

#ifdef CONFIG_NUMA
	memset(node_load, 0, sizeof(node_load));
#endif

	for_each_online_node(nid) {
		pg_data_t *pgdat = NODE_DATA(nid);

		/* Highly depends on if NUMA is configured.. */
		build_zonelists(pgdat);
	}
}

/**
 * sparse_memory_present_with_active_regions - Call memory_present for each active range
 * @nid: The node to call memory_present for. If MAX_NUMNODES, all nodes will be used.
 *
 * If an architecture guarantees that all ranges registered contain no holes and may
 * be freed, this function may be used instead of calling memory_present() manually.
 */
static void __init sparse_memory_present_with_active_regions(int nid)
{
	unsigned long start_pfn, end_pfn;
	int i, this_nid;

	for_each_mem_pfn_range(i, nid, &start_pfn, &end_pfn, &this_nid)
		memory_present(this_nid, start_pfn, end_pfn);
}

/*
 * This function is used to inspect for_each_zone_zonelist_nodemask
 * or mainly if the zonelist is built in the right way. Zones order
 * matter here, becasue page allocation use the same macro to walk
 * through zones.
 */
void dump_zonelists(void)
{
	int nid;
	struct zone *zone;
	struct zoneref *z;
	enum zone_type high_zoneidx = __MAX_NR_ZONES;

	for_each_online_node(nid) {
		pg_data_t *pg_data = NODE_DATA(nid);
		struct zonelist *zonelist = &pg_data->node_zonelists[0];

		pr_debug("Node %d Page Allocation Order\n", nid);
		for_each_zone_zonelist_nodemask(zone, z, zonelist, high_zoneidx, NULL) {
			pr_debug("   zone: node=%d, name=%s \t [%#lx - %#lx]\n",
				zone->zone_pgdat->node_id, zone->name,
				zone->zone_start_pfn << PAGE_SHIFT,
				((zone->zone_start_pfn + zone->spanned_pages) << PAGE_SHIFT) - 1);
		}
	}
}

void manager_meminfo(struct manager_sysinfo *val)
{
	val->totalram = totalram_pages;
	val->freeram = global_page_state(NR_FREE_PAGES);
	val->mem_unit = PAGE_SIZE;
}

void __init memory_init(void)
{
	sparse_memory_present_with_active_regions(MAX_NUMNODES);
	sparse_init();

	/* Will call free_area_init_nodes() inside */
	arch_zone_init();

	/*
	 * Build the allocation node + zone list
	 */
	build_all_zonelists();

	/* Put all avaiable memory to allocator */
	free_all_bootmem();

	dump_zonelists();
}

/*
 * allocate a large system hash table from bootmem
 * - it is assumed that the hash table must contain an exact power-of-2
 *   quantity of entries
 * - limit is the number of hash buckets, not the total allocation size
 */
void *__init alloc_large_system_hash(const char *tablename,
				     unsigned long bucketsize,
				     unsigned long numentries,
				     int scale,
				     int flags,
				     unsigned int *_hash_shift,
				     unsigned int *_hash_mask,
				     unsigned long low_limit,
				     unsigned long high_limit)
{
	unsigned long long max = high_limit;
	unsigned long log2qty, size;
	void *table = NULL;

	numentries = roundup_pow_of_two(numentries);
	max = min(max, 0x80000000ULL);

	if (numentries < low_limit)
		numentries = low_limit;
	if (numentries > max)
		numentries = max;

	log2qty = ilog2(numentries);

	do {
		size = bucketsize << log2qty;
		table = memblock_virt_alloc_nopanic(size, 0);
	} while (!table && size > PAGE_SIZE && --log2qty);

	if (!table)
		panic("Failed to allocate %s hash table\n", tablename);

	pr_info("%s hash table entries: %ld (order: %d, %lu bytes)\n",
		tablename, 1UL << log2qty, ilog2(size) - PAGE_SHIFT, size);

	if (_hash_shift)
		*_hash_shift = log2qty;
	if (_hash_mask)
		*_hash_mask = (1 << log2qty) - 1;

	return table;
}
