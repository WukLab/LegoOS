/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Things related to thread activities, such as fork(), exit().
 */

#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/memblock.h>

#include <processor/pcache.h>
#include <processor/pgtable.h>
#include <processor/processor.h>

#ifdef CONFIG_DEBUG_FORK
#define fork_debug(fmt, ...)						\
	pr_debug("%s(cpu%d): " fmt "\n", __func__, smp_processor_id(),	\
		__VA_ARGS__)
#else
static inline void fork_debug(const char *fmt, ...) { }
#endif

/*
 * Called when a new process is created.
 * This share the same purpose of dup_lego_mmap() at memory side.
 * Also, the vmainfo array is obtained at p2m_fork().
 */
int fork_dup_pcache(struct task_struct *dst_task,
		    struct mm_struct *dst_mm, struct mm_struct *src_mm,
		    void *_vmainfo)
{
	struct fork_reply_struct *fork_reply = _vmainfo;
	struct fork_vmainfo *vma, *vmas = fork_reply->vmainfos;
	int ret, i, nr_vmas = fork_reply->vma_count;
	unsigned long start, end, flags;

	/*
	 * We walk through pgtable based on vma range and flags.
	 * We need to wrprotect most of the pte entries..
	 */
	for (i = 0; i < nr_vmas; i++) {
		vma = &vmas[i];
		start = vma->vm_start;
		end = vma->vm_end;
		flags = vma->vm_flags;

		fork_debug("  [%d] [%#lx-%#lx] %#lx %#lx is_cow: %d",
			i, start, end, flags, (flags & (VM_SHARED | VM_WRITE)),
			is_cow_mapping(flags));
		ret = pcache_copy_page_range(dst_mm, src_mm,
					     start, end, flags, dst_task);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Called when a process exit
 * Cleanup all pcache lines
 *
 * TODO:
 * Anonymous: just free
 * File-backed: flush back
 *
 * Be careful against pcache eviction
 */
void pcache_process_exit(struct task_struct *tsk)
{
	/* will also free rmap */
	release_pgtable(tsk, PAGE_SIZE, TASK_SIZE);
}

/*
 * Called when a thread within a process exit.
 * This function will wait any pending pcache activities related to this thread
 * to finish. Pcache leftover cleanup is done by pcache_process_exit().
 */
void pcache_thread_exit(struct task_struct *tsk)
{

}
