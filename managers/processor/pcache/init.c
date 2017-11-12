/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/syscalls.h>
#include <lego/comp_processor.h>
#include <asm/io.h>

#include <processor/include/pcache.h>

u64 llc_cache_start;
u64 llc_cache_registered_size;

/* Final used size */
u64 llc_cache_size;

u32 llc_cacheline_size = PAGE_SIZE;
u32 llc_cachemeta_size = CONFIG_PCACHE_METADATA_SIZE;

/* nr_cachelines = nr_cachesets * associativity */
u64 nr_cachelines;
u64 nr_cachesets;
u32 llc_cache_associativity = 1 << CONFIG_PCACHE_ASSOCIATIVITY_SHIFT;

/* pages used by cacheline and metadata */
u64 nr_pages_cacheline;
u64 nr_pages_metadata;

/* original physical and ioremap'd virtual address */
u64 phys_start_cacheline;
u64 phys_start_metadata;
u64 virt_start_cacheline;
u64 virt_start_metadata;

/* Address bits usage */
u64 nr_bits_cacheline;
u64 nr_bits_set;
u64 nr_bits_tag;

u64 pcache_cacheline_mask;
u64 pcache_set_mask;
u64 pcache_tag_mask;

u64 pcache_way_cache_stride;
u64 pcache_way_meta_stride;

/*
 * We are using special memmap semantic.
 * Pcache pages are marked as *reserved* in memblock, so all
 * pages should have been marked as PageReserve by reserve_bootmem_region().
 */
static void pcache_sanity_check(void)
{
	int i;
	struct page *page;
	unsigned long nr_pages = llc_cache_registered_size / PAGE_SIZE;
	unsigned long va = virt_start_cacheline;

	for (i = 0; i < nr_pages; i++, va += PAGE_SIZE) {
		page = virt_to_page(va);

		if (unlikely(!PageReserved(page))) {
			dump_page(page, NULL);
			panic("Bug indeed");
		}
	}
}

void __init pcache_init(void)
{
	u64 nr_cachelines_per_page, nr_units;
	u64 unit_size;

	if (llc_cache_start == 0 || llc_cache_registered_size == 0)
		panic("Processor cache not registered, memmap $ needed!");

	if (!IS_ENABLED(CONFIG_LEGO_SPECIAL_MEMMAP))
		panic("Require special memmap $ semantic!");

	virt_start_cacheline = (unsigned long)phys_to_virt(llc_cache_start);

	/*
	 * Clear any stale value
	 * This may happen if running on QEMU.
	 * Not sure about physical machine.
	 */
	memset((void *)virt_start_cacheline, 0, llc_cache_registered_size);

	pcache_sanity_check();

	nr_cachelines_per_page = PAGE_SIZE / llc_cachemeta_size;
	unit_size = nr_cachelines_per_page * llc_cacheline_size;
	unit_size += PAGE_SIZE;

	/*
	 * nr_cachelines_per_page must already be a power of 2.
	 * We must make nr_units a power of 2, then the total
	 * number of cache lines can be a power of 2, too.
	 */
	nr_units = llc_cache_registered_size / unit_size;
	nr_units = rounddown_pow_of_two(nr_units);

	/* final valid used size */
	llc_cache_size = nr_units * unit_size;

	nr_cachelines = nr_units * nr_cachelines_per_page;
	nr_cachesets = nr_cachelines / llc_cache_associativity;

	nr_pages_cacheline = nr_cachelines;
	nr_pages_metadata = nr_units;

	/* Save physical/virtual starting address */
	phys_start_cacheline = llc_cache_start;
	phys_start_metadata = phys_start_cacheline + nr_pages_cacheline * PAGE_SIZE;
	virt_start_metadata = virt_start_cacheline + nr_pages_cacheline * PAGE_SIZE;

	nr_bits_cacheline = ilog2(llc_cacheline_size);
	nr_bits_set = ilog2(nr_cachesets);
	nr_bits_tag = 64 - nr_bits_cacheline - nr_bits_set;

	pr_info("Processor LLC Configurations:\n");
	pr_info("    PhysStart:         %#llx\n",	llc_cache_start);
	pr_info("    VirtStart:         %#llx\n",	virt_start_cacheline);
	pr_info("    Registered Size:   %#llx\n",	llc_cache_registered_size);
	pr_info("    Actual Used Size:  %#llx\n",	llc_cache_size);
	pr_info("    NR cachelines:     %llu\n",	nr_cachelines);
	pr_info("    Associativity:     %u\n",		llc_cache_associativity);
	pr_info("    NR Sets:           %llu\n",	nr_cachesets);
	pr_info("    Cacheline size:    %u B\n",	llc_cacheline_size);
	pr_info("    Metadata size:     %u B\n",	llc_cachemeta_size);

	pcache_cacheline_mask = (1ULL << nr_bits_cacheline) - 1;
	pcache_set_mask = ((1ULL << (nr_bits_cacheline + nr_bits_set)) - 1) & ~pcache_cacheline_mask;
	pcache_tag_mask = ~((1ULL << (nr_bits_cacheline + nr_bits_set)) - 1);

	pr_info("    NR cacheline bits: %2llu [%2llu - %2llu] %#llx\n",
		nr_bits_cacheline,
		0ULL,
		nr_bits_cacheline - 1,
		pcache_cacheline_mask);
	pr_info("    NR set-index bits: %2llu [%2llu - %2llu] %#llx\n",
		nr_bits_set,
		nr_bits_cacheline,
		nr_bits_cacheline + nr_bits_set - 1,
		pcache_set_mask);
	pr_info("    NR tag bits:       %2llu [%2llu - %2llu] %#llx\n",
		nr_bits_tag,
		nr_bits_cacheline + nr_bits_set,
		nr_bits_cacheline + nr_bits_set + nr_bits_tag - 1,
		pcache_tag_mask);

	pr_info("    NR pages for data: %llu\n",	nr_pages_cacheline);
	pr_info("    NR pages for meta: %llu\n",	nr_pages_metadata);
	pr_info("    Cacheline (pa) range:   [%#18llx - %#18llx]\n",
		phys_start_cacheline, phys_start_metadata - 1);
	pr_info("    Metadata (pa) range:    [%#18llx - %#18llx]\n",
		phys_start_metadata, phys_start_metadata + nr_pages_metadata * PAGE_SIZE - 1);

	pr_info("    Cacheline (va) range:   [%#18llx - %#18llx]\n",
		virt_start_cacheline, virt_start_metadata - 1);
	pr_info("    Metadata (va) range:    [%#18llx - %#18llx]\n",
		virt_start_metadata, virt_start_metadata + nr_pages_metadata * PAGE_SIZE - 1);

	pcache_way_cache_stride = nr_cachesets * llc_cacheline_size;
	pcache_way_meta_stride =  nr_cachesets * llc_cachemeta_size;
	pr_info("    Way cache stride:  %#llx\n", pcache_way_cache_stride);
	pr_info("    Way meta stride:   %#llx\n", pcache_way_meta_stride);
}

/**
 * pcache_range_register
 * @start: physical address of the first byte of the cache
 * @size: size of the cache
 *
 * Register a consecutive physical memory range as the last-level cache for
 * processor component. It is invoked at early boot before everything about
 * memory is initialized. For x86, this is registered during the parsing of
 * memmap=N$N command line option.
 *
 * If CONFIG_LEGO_SPECIAL_MEMMAP is ON, this range will not be bailed out
 * from e820 table, it is marked as reserved in memblock. So pages within
 * this range still have `struct page`, yeah!
 */
int __init pcache_range_register(u64 start, u64 size)
{
	if (WARN_ON(!start && !size))
		return -EINVAL;

	if (WARN_ON(offset_in_page(start) || offset_in_page(size)))
		return -EINVAL;

	if (llc_cache_start || llc_cache_registered_size)
		panic("Remove extra memmap from kernel parameters!");

	llc_cache_start = start;
	llc_cache_registered_size = size;

	return 0;
}
