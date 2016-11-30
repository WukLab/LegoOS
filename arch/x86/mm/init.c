/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


#include <asm/asm.h>
#include <asm/e820.h>
#include <asm/page.h>
#include <asm/setup.h>
#include <asm/pgtable.h>

#include <lego/mm.h>
#include <lego/numa.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/memblock.h>

static unsigned long __initdata pgt_buf_start;
static unsigned long __initdata pgt_buf_end;
static unsigned long __initdata pgt_buf_top;
static bool __initdata can_use_brk_pgt = true;

/*
 * By default
 *  3 4k for initial PMD_SIZE,
 *  3 4k for 0-ISA_END_ADDRESS.
 */
#define INIT_PGD_PAGE_COUNT      6
#define INIT_PGT_BUF_SIZE	(INIT_PGD_PAGE_COUNT * PAGE_SIZE)

RESERVE_BRK(early_pgt_alloc, INIT_PGT_BUF_SIZE);

void  __init early_alloc_pgt_buf(void)
{
	unsigned long tables = INIT_PGT_BUF_SIZE;
	phys_addr_t base;

	base = __pa(extend_brk(tables, PAGE_SIZE));

	pgt_buf_start = base >> PAGE_SHIFT;
	pgt_buf_end = pgt_buf_start;
	pgt_buf_top = pgt_buf_start + (tables >> PAGE_SHIFT);
}

struct map_range {
	unsigned long start;
	unsigned long end;
	unsigned page_size_mask;
};
#define NR_RANGE_MR 5

static int page_size_mask;

/*
 * TODO:
 * Using 4KB for now; May switch to 1GB later
 */
static void __init probe_page_size_mask(void)
{
	page_size_mask |= 1 << PG_LEVEL_4K;
}

static const char *page_size_string(struct map_range *mr)
{
	static const char str_1g[] = "1G";
	static const char str_2m[] = "2M";
	static const char str_4k[] = "4k";

	if (mr->page_size_mask & (1<<PG_LEVEL_1G))
		return str_1g;

	if (mr->page_size_mask & (1<<PG_LEVEL_2M))
		return str_2m;

	return str_4k;
}

/*
 * adjust the page_size_mask for small range to go with
 *	big page size instead small one if nearby are ram too.
 */
static void adjust_range_page_size_mask(struct map_range *mr, int nr_range)
{
	int i;

	for (i = 0; i < nr_range; i++) {
		if ((page_size_mask & (1<<PG_LEVEL_2M)) &&
		    !(mr[i].page_size_mask & (1<<PG_LEVEL_2M))) {
			unsigned long start = round_down(mr[i].start, PMD_SIZE);
			unsigned long end = round_up(mr[i].end, PMD_SIZE);

			if (memblock_is_region_memory(start, end - start))
				mr[i].page_size_mask |= 1<<PG_LEVEL_2M;
		}
		if ((page_size_mask & (1<<PG_LEVEL_1G)) &&
		    !(mr[i].page_size_mask & (1<<PG_LEVEL_1G))) {
			unsigned long start = round_down(mr[i].start, PUD_SIZE);
			unsigned long end = round_up(mr[i].end, PUD_SIZE);

			if (memblock_is_region_memory(start, end - start))
				mr[i].page_size_mask |= 1<<PG_LEVEL_1G;
		}
	}
}

static int save_mr(struct map_range *mr, int nr_range,
		   unsigned long start_pfn, unsigned long end_pfn,
		   unsigned long page_size_mask)
{
	if (start_pfn < end_pfn) {
		if (nr_range >= NR_RANGE_MR)
			panic("run out of nr_range\n");
		mr[nr_range].start = start_pfn<<PAGE_SHIFT;
		mr[nr_range].end   = end_pfn<<PAGE_SHIFT;
		mr[nr_range].page_size_mask = page_size_mask;
		nr_range++;
	}

	return nr_range;
}

static int split_mem_range(struct map_range *mr, int nr_range,
			   unsigned long start, unsigned long end)
{
	unsigned long start_pfn, end_pfn, limit_pfn;
	unsigned long pfn;
	int i;

	limit_pfn = PFN_DOWN(end);

	/* head if not big page alignment ? */
	pfn = start_pfn = PFN_DOWN(start);
	end_pfn = round_up(pfn, PFN_DOWN(PMD_SIZE));

	if (end_pfn > limit_pfn)
		end_pfn = limit_pfn;
	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn, 0);
		pfn = end_pfn;
	}

	/* big page (2M) range */
	start_pfn = round_up(pfn, PFN_DOWN(PMD_SIZE));
	end_pfn = round_up(pfn, PFN_DOWN(PUD_SIZE));
	if (end_pfn > round_down(limit_pfn, PFN_DOWN(PMD_SIZE)))
		end_pfn = round_down(limit_pfn, PFN_DOWN(PMD_SIZE));

	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask & (1<<PG_LEVEL_2M));
		pfn = end_pfn;
	}

	/* big page (1G) range */
	start_pfn = round_up(pfn, PFN_DOWN(PUD_SIZE));
	end_pfn = round_down(limit_pfn, PFN_DOWN(PUD_SIZE));
	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask &
				 ((1<<PG_LEVEL_2M)|(1<<PG_LEVEL_1G)));
		pfn = end_pfn;
	}

	/* tail is not big page (1G) alignment */
	start_pfn = round_up(pfn, PFN_DOWN(PMD_SIZE));
	end_pfn = round_down(limit_pfn, PFN_DOWN(PMD_SIZE));
	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask & (1<<PG_LEVEL_2M));
		pfn = end_pfn;
	}

	/* tail is not big page (2M) alignment */
	start_pfn = pfn;
	end_pfn = limit_pfn;
	nr_range = save_mr(mr, nr_range, start_pfn, end_pfn, 0);

	adjust_range_page_size_mask(mr, nr_range);

	/* try to merge same page size and continuous */
	for (i = 0; nr_range > 1 && i < nr_range - 1; i++) {
		unsigned long old_start;
		if (mr[i].end != mr[i+1].start ||
		    mr[i].page_size_mask != mr[i+1].page_size_mask)
			continue;
		/* move it */
		old_start = mr[i].start;
		memmove(&mr[i], &mr[i+1],
			(nr_range - 1 - i) * sizeof(struct map_range));
		mr[i--].start = old_start;
		nr_range--;
	}

	for (i = 0; i < nr_range; i++)
		pr_debug(" [mem %#010lx-%#010lx] page %s\n",
				mr[i].start, mr[i].end - 1,
				page_size_string(&mr[i]));

	return nr_range;
}

/*
 * Create page table mapping for the physical memory for specific physical
 * addresses. The virtual and physical addresses have to be aligned on PMD level
 * down. It returns the last physical address mapped.
 */
unsigned long
kernel_physical_mapping_init(unsigned long paddr_start,
			     unsigned long paddr_end,
			     unsigned long page_size_mask)
{
	return 0;
}

/*
 * Setup the direct mapping of the physical memory at PAGE_OFFSET.
 * This runs before bootmem is initialized and gets pages directly from
 * the physical memory. To access them they are temporarily mapped.
 */
unsigned long init_memory_mapping(unsigned long start,
				  unsigned long end)
{
	struct map_range mr[NR_RANGE_MR];
	unsigned long ret = 0;
	int nr_range, i;

	pr_debug("init_memory_mapping: [mem %#010lx-%#010lx]\n",
	       start, end - 1);

	memset(mr, 0, sizeof(mr));
	nr_range = split_mem_range(mr, 0, start, end);

	for (i = 0; i < nr_range; i++)
		ret = kernel_physical_mapping_init(mr[i].start, mr[i].end,
						   mr[i].page_size_mask);

	//add_pfn_range_mapped(start >> PAGE_SHIFT, ret >> PAGE_SHIFT);

	return ret >> PAGE_SHIFT;
}

/*
 * We need to iterate through the E820 memory map and create direct mappings
 * for only E820_RAM and E820_KERN_RESERVED regions. We cannot simply
 * create direct mappings for all pfns from [0 to max_low_pfn) and
 * [4GB to max_pfn) because of possible memory holes in high addresses
 * that cannot be marked as UC by fixed/variable range MTRRs.
 * Depending on the alignment of E820 ranges, this may possibly result
 * in using smaller size (i.e. 4K instead of 2M or 1G) page tables.
 *
 * init_mem_mapping() calls init_range_memory_mapping() with big range.
 * That range would have hole in the middle or ends, and only ram parts
 * will be mapped in init_range_memory_mapping().
 */
static unsigned long __init init_range_memory_mapping(
					   unsigned long r_start,
					   unsigned long r_end)
{
	unsigned long start_pfn, end_pfn;
	unsigned long mapped_ram_size = 0;
	int i;

	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, NULL) {
		u64 start = clamp_val(PFN_PHYS(start_pfn), r_start, r_end);
		u64 end = clamp_val(PFN_PHYS(end_pfn), r_start, r_end);
		if (start >= end)
			continue;

		/*
		 * If it is overlapping with brk pgt, we need to
		 * alloc pgt buf from memblock instead.
		 */
		can_use_brk_pgt = max(start, (u64)pgt_buf_end<<PAGE_SHIFT) >=
				    min(end, (u64)pgt_buf_top<<PAGE_SHIFT);
		init_memory_mapping(start, end);
		mapped_ram_size += end - start;
		can_use_brk_pgt = true;
	}

	return mapped_ram_size;
}

static unsigned long __init get_new_step_size(unsigned long step_size)
{
	/*
	 * Initial mapped size is PMD_SIZE (2M).
	 * We can not set step_size to be PUD_SIZE (1G) yet.
	 * In worse case, when we cross the 1G boundary, and
	 * PG_LEVEL_2M is not set, we will need 1+1+512 pages (2M + 8k)
	 * to map 1G range with PTE. Hence we use one less than the
	 * difference of page table level shifts.
	 *
	 * Don't need to worry about overflow in the top-down case, on 32bit,
	 * when step_size is 0, round_down() returns 0 for start, and that
	 * turns it into 0x100000000ULL.
	 * In the bottom-up case, round_up(x, 0) returns 0 though too, which
	 * needs to be taken into consideration by the code below.
	 */
	return step_size << (PMD_SHIFT - PAGE_SHIFT - 1);
}

static unsigned long min_pfn_mapped;

/**
 * memory_map_top_down - Map [map_start, map_end) top down
 * @map_start: start address of the target memory range
 * @map_end: end address of the target memory range
 *
 * This function will setup direct mapping for memory range
 * [map_start, map_end) in top-down. That said, the page tables
 * will be allocated at the end of the memory, and we map the
 * memory in top-down.
 */
static void __init memory_map_top_down(unsigned long map_start,
				       unsigned long map_end)
{
	unsigned long real_end, start, last_start;
	unsigned long step_size;
	unsigned long addr;
	unsigned long mapped_ram_size = 0;

	/* xen has big range in reserved near end of ram, skip it at first.*/
	addr = memblock_find_in_range(map_start, map_end, PMD_SIZE, PMD_SIZE);
	real_end = addr + PMD_SIZE;

	/* step_size need to be small so pgt_buf from BRK could cover it */
	step_size = PMD_SIZE;

	/* will get exact value next */
	max_pfn_mapped = 0;
	min_pfn_mapped = real_end >> PAGE_SHIFT;
	last_start = start = real_end;

	/*
	 * We start from the top (end of memory) and go to the bottom.
	 * The memblock_find_in_range() gets us a block of RAM from the
	 * end of RAM in [min_pfn_mapped, max_pfn_mapped) used as new pages
	 * for page table.
	 */
	while (last_start > map_start) {
		if (last_start > step_size) {
			start = round_down(last_start - 1, step_size);
			if (start < map_start)
				start = map_start;
		} else
			start = map_start;
		mapped_ram_size += init_range_memory_mapping(start,
							last_start);
		last_start = start;
		min_pfn_mapped = last_start >> PAGE_SHIFT;
		if (mapped_ram_size >= step_size)
			step_size = get_new_step_size(step_size);
	}

	if (real_end < map_end)
		init_range_memory_mapping(real_end, map_end);
}

void __init init_mem_mapping(void)
{
	unsigned long end;

	probe_page_size_mask();

	end = max_pfn << PAGE_SHIFT;

	init_memory_mapping(0, ISA_END_ADDRESS);

	/*
	 * X86 maps top->down direction
	 */
	memory_map_top_down(ISA_END_ADDRESS, end);
}
