/*
 * Copyright (c) 2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _PROCESSOR_MANAGER_PGTABLE_H_
#define _PROCESSOR_MANAGER_PGTABLE_H_

#include <lego/mm.h>
#include <lego/comp_common.h>

void free_pgd_range(struct mm_struct *mm,
		    unsigned long addr, unsigned long end,
		    unsigned long floor, unsigned long ceiling);

void unmap_page_range(struct mm_struct *mm,
		      unsigned long addr, unsigned long end);

int copy_page_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		    struct p_vm_area_struct *vma);

unsigned long move_page_tables(struct mm_struct *mm, unsigned long old_addr,
			       unsigned long new_addr, unsigned long len);

void release_emulated_pgtable(struct mm_struct *mm,
			      unsigned long __user start,
			      unsigned long __user end);

#endif /* _PROCESSOR_MANAGER_PGTABLE_H_ */
