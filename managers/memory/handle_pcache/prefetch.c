/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/fit_ibapi.h>
#include <lego/ratelimit.h>
#include <lego/comp_memory.h>
#include <lego/comp_storage.h>
#include <memory/vm.h>
#include <memory/pid.h>
#include <processor/pcache.h>

#ifdef CONFIG_MEM_PREFETCH
void do_mmap_prefetch(struct lego_task_struct *p, u64 vaddr,
		      u32 flags, u32 nr_pages)
{
	struct vm_area_struct *vma;
	struct lego_mm_struct *mm = p->mm;
	u32 real_nr_pages = nr_pages;
	u32 empty_entries;

	down_read(&mm->mmap_sem);

	vma = find_vma(mm, vaddr);

	if (unlikely(!vma)) {
		goto unlock;
	}

	if (unlikely(vma_is_anonymous(vma))) {
		goto unlock;
	}

	/* file backed pages */
	if (unlikely(round_down(vaddr, PAGE_SIZE) + PAGE_SIZE*nr_pages)
			> vma->vm_end)
		real_nr_pages = (vma->vm_end - round_down(vaddr, PAGE_SIZE))/PAGE_SIZE;

	empty_entries = count_empty_entries(vma, vaddr, real_nr_pages);
	if (5*empty_entries < 4*real_nr_pages)
		goto unlock;
	/* handle_lego_faults */
	handle_lego_mmap_faults(vma, vaddr, flags, real_nr_pages);

unlock:
	up_read(&mm->mmap_sem);
	return;
}
#else
void do_mmap_prefetch(struct lego_task_struct *p, u64 vaddr,
		      u32 flags, u32 nr_pages)
{ }
#endif /* CONFIG_MEM_PREFETCH */
