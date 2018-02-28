/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Things about bulk pgtable operations, mostly for fork, exit.
 * Probably we also want to move pcache_zap, pcache_move here.
 * Also, the free pool code.
 */

#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/memblock.h>

#include <processor/pcache.h>
#include <processor/processor.h>

/*
 * Called when a new process is created.
 * This share the same purpose of dup_lego_mmap() from memory side.
 */
int fork_dup_pcache(struct mm_struct *mm, struct mm_struct *oldmm)
{
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
void pcache_process_exit(struct mm_struct *mm)
{
	print_pcache_events();
}

/*
 * Called when a thread within a process exit.
 * This function will wait any pending pcache activities related to this thread
 * to finish. Pcache leftover cleanup is done by pcache_process_exit().
 */
void pcache_thread_exit(struct task_struct *tsk)
{

}
