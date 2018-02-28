/*
 * Copyright (c) 2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Your friends to play with user pgtables.
 * These operations are only needed by processor manager.
 * Basic pgtable operations in core kernel can satisfy memory manager.
 */

#ifndef _LEGO_PROCESSOR_PGTABLE_H_
#define _LEGO_PROCESSOR_PGTABLE_H_

#include <lego/mm.h>
#include <lego/comp_common.h>

void dump_page_tables(struct task_struct *tsk,
		      unsigned long __user start, unsigned long __user end);

void free_pgd_range(struct mm_struct *mm,
		    unsigned long __user addr, unsigned long __user end);

void unmap_page_range(struct mm_struct *mm,
		      unsigned long addr, unsigned long end);

/* Callback for fork() */
int pcache_copy_page_range(struct mm_struct *dst, struct mm_struct *src,
			   unsigned long addr, unsigned long end,
			   unsigned long vm_flags, struct task_struct *dst_task);

void release_pgtable(struct task_struct *tsk,
		     unsigned long __user start, unsigned long __user end);

/* Callback for mremap() */
unsigned long move_page_tables(struct task_struct *tsk,
			       unsigned long __user old_addr,
			       unsigned long __user new_addr, unsigned long len);

#endif /* _LEGO_PROCESSOR_PGTABLE_H_ */
