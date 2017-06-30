/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This code runs on *memory-component* only!
 * Most of them are called during loading the program from loader.
 */
#ifndef CONFIG_COMP_MEMORY
# error Configuration & Makefile Error
#endif

#include <lego/mm.h>
#include <lego/kernel.h>
#include <lego/comp_memory.h>

static unsigned long
arch_get_unmapped_area(struct lego_task_struct *p, struct lego_file *filp,
		unsigned long addr, unsigned long len, unsigned long pgoff,
		unsigned long flags)
{
	struct lego_mm_struct *mm = p->mm;
	struct vm_area_struct *vma;
	struct vm_unmapped_area_info info;
	unsigned long begin, end;

	if (flags & MAP_FIXED)
		return addr;

	begin = mm->mmap_legacy_base;
	end = TASK_SIZE;

	if (len > end)
		return -ENOMEM;

	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma(mm, addr);
		if (end - len >= addr &&
		    (!vma || addr + len <= vma->vm_start))
			return addr;
	}

	info.flags = 0;
	info.length = len;
	info.low_limit = begin;
	info.high_limit = end;
	info.align_mask = 0;
	info.align_offset = pgoff << PAGE_SHIFT;

	return vm_unmapped_area(p, &info);
}

static unsigned long
arch_get_unmapped_area_topdown(struct lego_task_struct *p, struct lego_file *filp,
		const unsigned long addr0, const unsigned long len,
		const unsigned long pgoff, const unsigned long flags)
{
	struct vm_area_struct *vma;
	struct lego_mm_struct *mm = p->mm;
	unsigned long addr = addr0;
	struct vm_unmapped_area_info info;

	if (len > TASK_SIZE)
		return -ENOMEM;

	if (flags & MAP_FIXED)
		return addr;

	/* requesting a specific address */
	if (addr) {
		addr = PAGE_ALIGN(addr);
		vma = find_vma(mm, addr);
		if (TASK_SIZE - len >= addr &&
				(!vma || addr + len <= vma->vm_start))
			return addr;
	}

	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
	info.length = len;
	info.low_limit = PAGE_SIZE;
	info.high_limit = mm->mmap_base;
	info.align_mask = 0;
	info.align_offset = pgoff << PAGE_SHIFT;

	addr = vm_unmapped_area(p, &info);
	if (!(addr & ~PAGE_MASK))
		return addr;
	BUG_ON(addr != -ENOMEM);

	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	return arch_get_unmapped_area(p, filp, addr0, len, pgoff, flags);
}

/*
 * Top of mmap area (just below the process stack).
 *
 * Leave an at least 128 MB hole.
 */
#define MIN_GAP	(128*1024*1024UL)
#define MAX_GAP	(TASK_SIZE/6*5)

static unsigned long mmap_base(void)
{
	unsigned long gap = 0; /* TODO: rlimit */

	if (gap < MIN_GAP)
		gap = MIN_GAP;
	else if (gap > MAX_GAP)
		gap = MAX_GAP;

	return PAGE_ALIGN(TASK_SIZE - gap);
}

/*
 * This function, called very early during the creation of a new
 * process VM image, sets up which VM layout function to use:
 */
void arch_pick_mmap_layout(struct lego_mm_struct *lego_mm)
{
	lego_mm->mmap_legacy_base = TASK_UNMAPPED_BASE;
	lego_mm->mmap_base = mmap_base();
	lego_mm->get_unmapped_area = arch_get_unmapped_area_topdown;
}
