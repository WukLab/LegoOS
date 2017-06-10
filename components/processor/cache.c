/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Lego Processor Last-Level Cache Management
 */

#include <lego/mm.h>
#include <lego/log2.h>
#include <lego/kernel.h>

static u64 llc_cache_start;
static u64 llc_cache_registered_size;

/* Final used size */
static u64 llc_cache_size;

static u32 llc_cacheline_size = PAGE_SIZE;
static u32 llc_cachemeta_size = CONFIG_PROCESSOR_LLC_METADATA_SIZE;

/* nr_cachelines = nr_cachesets * associativity */
static u64 nr_cachelines;
static u64 nr_cachesets;
static u32 llc_cache_associativity = CONFIG_PROCESSOR_LLC_ASSOCIATIVITY;

static u64 nr_pages_cacheline;
static u64 nr_pages_metadata;
static u64 phys_start_cacheline;
static u64 phys_start_metadata;

/* Address bits usage */
static u64 nr_bits_cacheline;
static u64 nr_bits_setindex;
static u64 nr_bits_tag;

void __init processor_cache_init(void)
{
	u64 nr_cachelines_per_page, nr_units;
	u64 unit_size;

	if (llc_cache_start == 0 || llc_cache_registered_size == 0)
		panic("Processor cache not registered.");

	if (!is_power_of_2(llc_cache_associativity))
		panic("Associativity is not a power of 2.");

	nr_cachelines_per_page = PAGE_SIZE / llc_cachemeta_size;
	unit_size = nr_cachelines_per_page * llc_cacheline_size;
	unit_size += PAGE_SIZE;

	/*
	 * nr_cachelines_per_page must already be a power of 2.
	 * We must make nr_units a power of 2, then the total
	 * number of cache lines can be a power of 2, too.
	 */
	nr_units = llc_cache_registered_size / unit_size;
	pr_info("Original nr_units:  %Lu\n", nr_units);
	nr_units = rounddown_pow_of_two(nr_units);
	llc_cache_size = nr_units * unit_size;
	pr_info("Rounddown nr_units: %Lu\n", nr_units);

	nr_cachelines = nr_units * nr_cachelines_per_page;
	nr_cachesets = nr_cachelines / llc_cache_associativity;

	nr_pages_cacheline = nr_cachelines;
	nr_pages_metadata = nr_units;
	phys_start_cacheline = llc_cache_start;
	phys_start_metadata = phys_start_cacheline + nr_pages_cacheline * PAGE_SIZE;

	nr_bits_cacheline = ilog2(llc_cacheline_size);
	nr_bits_setindex = ilog2(nr_cachesets);
	nr_bits_tag = 64 - nr_bits_cacheline - nr_bits_setindex;

	pr_info("Processor LLC Configurations:\n");
	pr_info("    Start:             %#llx\n",	llc_cache_start);
	pr_info("    Registered Size:   %#llx\n",	llc_cache_registered_size);
	pr_info("    Used Size:         %#llx\n",	llc_cache_size);
	pr_info("    NR cachelines:     %llu\n",	nr_cachelines);
	pr_info("    Associativity:     %u\n",		llc_cache_associativity);
	pr_info("    NR Sets:           %llu\n",	nr_cachesets);
	pr_info("    Cacheline size:    %u B\n",	llc_cacheline_size);
	pr_info("    Metadata size:     %u B\n",	llc_cachemeta_size);
	pr_info("    NR cacheline bits: %llu\n",	nr_bits_cacheline);
	pr_info("    NR set-index bits: %llu\n",	nr_bits_setindex);
	pr_info("    NR tag bits:       %llu\n",	nr_bits_tag);

	pr_info("    NR pages for data: %llu\n",	nr_pages_cacheline);
	pr_info("    NR pages for meta: %llu\n",	nr_pages_metadata);
	pr_info("    cacheline range:   [%#18llx - %#18llx]\n",
		phys_start_cacheline, phys_start_metadata - 1);
	pr_info("    metadata range:    [%#18llx - %#18llx]\n",
		phys_start_metadata, phys_start_metadata + nr_pages_metadata * PAGE_SIZE - 1);
}

int cacheline_fill(unsigned long missing_vaddr)
{
	return 0;
}

/**
 * processor_cache_range_register
 * @start: physical address of the first byte of the cache
 * @size: size of the cache
 *
 * Register a consecutive physical memory range as the last-level cache for
 * processor component. It is invoked at early boot before everything about
 * memory is initialized. For x86, this is registered during the parsing of
 * memmap=N$N command line option.
 */
int __init processor_cache_range_register(u64 start, u64 size)
{
	if (WARN_ON(!start && !size))
		return -EINVAL;

	llc_cache_start = start;
	llc_cache_registered_size = size;

	return 0;
}
