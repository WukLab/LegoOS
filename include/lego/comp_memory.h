/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_COMP_MEMORY_H_
#define _LEGO_COMP_MEMORY_H_

#include <lego/mm.h>

#define PROT_READ	0x01		/* page can be read */
#define PROT_WRITE	0x02		/* page can be written */
#define PROT_EXEC	0x04		/* page can be executed */
#define PROT_SEM	0x08		/* page may be used for atomic ops */
#define PROT_NONE	0x00		/* page can not be accessed */

#define MAP_SHARED	0x01		/* Share changes */
#define MAP_PRIVATE	0x02		/* Changes are private */
#define MAP_TYPE	0x0f		/* Mask for type of mapping */
#define MAP_FIXED	0x10		/* Interpret addr exactly */
#define MAP_ANONYMOUS	0x20		/* don't use a file */

/*
 * This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define TASK_UNMAPPED_BASE	(PAGE_ALIGN(TASK_SIZE / 3))

struct lego_task_struct;
struct lego_file;

struct lego_mm_struct {
	struct vm_area_struct *mmap;
	unsigned long highest_vm_end;

	unsigned long (*get_unmapped_area)(struct lego_task_struct *p,
				struct lego_file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);
	unsigned long mmap_base;		/* base of mmap area */
	unsigned long mmap_legacy_base;         /* base of mmap area in bottom-up allocations */
	unsigned long task_size;		/* size of task vm space */

	pgd_t *pgd;
	int map_count;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long start_brk, brk, start_stack;
	unsigned long arg_start, arg_end, env_start, env_end;

	struct lego_task_struct *task;
};

struct lego_task_struct {
	unsigned long node;
	unsigned long pid;
	unsigned long gpid;

	struct lego_mm_struct *mm;
};

#define MAX_FILENAME_LEN 128
struct lego_file {
	const char filename[MAX_FILENAME_LEN];
};

#ifdef CONFIG_COMP_MEMORY
void __init memory_component_init(void);
#else
static inline void memory_component_init(void) { }
#endif

struct vm_unmapped_area_info {
#define VM_UNMAPPED_AREA_TOPDOWN 1
	unsigned long flags;
	unsigned long length;
	unsigned long low_limit;
	unsigned long high_limit;
	unsigned long align_mask;
	unsigned long align_offset;
};

unsigned long
unmapped_area(struct lego_task_struct *p, struct vm_unmapped_area_info *info);
unsigned long
unmapped_area_topdown(struct lego_task_struct *p, struct vm_unmapped_area_info *info);

/*
 * Search for an unmapped address range.
 *
 * We are looking for a range that:
 * - does not intersect with any VMA;
 * - is contained within the [low_limit, high_limit) interval;
 * - is at least the desired size.
 * - satisfies (begin_addr & align_mask) == (align_offset & align_mask)
 */
static inline unsigned long
vm_unmapped_area(struct lego_task_struct *p, struct vm_unmapped_area_info *info)
{
	if (info->flags & VM_UNMAPPED_AREA_TOPDOWN)
		return unmapped_area_topdown(p, info);
	else
		return unmapped_area(p, info);
}

void arch_pick_mmap_layout(struct lego_mm_struct *mm);

/* Look up the first VMA which satisfies  addr < vm_end,  NULL if none. */
struct vm_area_struct *find_vma(struct lego_mm_struct *mm, unsigned long addr);

#endif /* _LEGO_COMP_MEMORY_H_ */
