/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file serves as unit test for file dist_mmap.c
 */

#include <lego/slab.h>
#include <processor/distvm.h>

static void test_map_find(struct mm_struct *mm, unsigned long addr, 
			  unsigned long len, int node)
{
	static int cases = 0;
	unsigned long end = addr + len;

	cases++;
	map_mnode(mm, addr, len, node);
	if (get_memory_node(mm, addr) != node)
		goto bad;

	if (VMR_ALIGN(end) == end)
		end -= VM_GRANULARITY;

	if (get_memory_node(mm, end) != node)
		goto bad;

	end += VM_GRANULARITY;
	if (get_memory_node(mm, end) == node)
		goto bad;

	vma_debug("success! case: %d\n", cases);
	return;
bad:
	vma_debug("fail! case: %d\n", cases);
}

void prcsr_vma_unit_test(void)
{
	int ret = 0;
	struct mm_struct * mm;

	vma_debug("Start unit test\n");
	mm = kmalloc(sizeof(struct mm_struct), GFP_KERNEL);
	if(!mm) {
		vma_debug("failed to allocate memory, exit test\n");
		return;
	}
	vma_debug("initialize vm range array\n");
	ret = distvm_init(mm, 1);
	vma_debug("initialization completed with ret code %d\n", ret);

	vma_debug("testing map and unmap\n");

	test_map_find(mm, 0, VM_GRANULARITY, 2);
	test_map_find(mm, 0x28f18abc9684, 0x2327829384, 3);
	test_map_find(mm, 0x3ff18abc9684, 0xfe7285b124, 4);

	distvm_exit(mm);
	vma_debug("Done unit test\n");
}
