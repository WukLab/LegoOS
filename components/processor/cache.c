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
#include <lego/kernel.h>

static u64 llc_cache_start;
static u64 llc_cache_size;
static u32 llc_cache_associativity = CONFIG_PROCESSOR_LLC_ASSOCIATIVITY;

void __init processor_cache_init(void)
{
	if (llc_cache_start == 0 || llc_cache_size == 0)
		panic("Processor cache not registered.");

	pr_info("Processor LLC Configurations:\n");
	pr_info("    start:            %#llx\n", llc_cache_start);
	pr_info("    size:             %#llx\n", llc_cache_size);
	pr_info("    associativity:    %d\n", llc_cache_associativity);
	pr_info("    cacheline size:   %lu B\n", PAGE_SIZE);
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
	llc_cache_size = size;

	return 0;
}
