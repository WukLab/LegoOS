/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/io.h>
#include <asm/page.h>

#include <lego/mm.h>
#include <lego/numa.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/memblock.h>

static char * const zone_names[MAX_NR_ZONES] = {
#ifdef CONFIG_ZONE_DMA
	 "DMA",
#endif
#ifdef CONFIG_ZONE_DMA32
	 "DMA32",
#endif
	 "Normal",
};

static unsigned long arch_zone_lowest_possible_pfn[MAX_NR_ZONES];
static unsigned long arch_zone_highest_possible_pfn[MAX_NR_ZONES];

/*
 * Set up the zone data structures:
 *   - mark all pages reserved
 *   - mark all memory queues empty
 *   - clear the memory bitmaps
 *
 * NOTE: pgdat should get zeroed by caller.
 */
static void __init free_area_init_core(void)
{
}

void __init free_area_init_node(int nid, unsigned long *zones_size,
				unsigned long node_start_pfn,
				unsigned long *zholes_size)
{
	free_area_init_core();
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

}

void __init memory_init(void)
{
	arch_zone_init();
}
