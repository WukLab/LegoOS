/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/comp_memory.h>
#include "../include/vm.h"
#include "../include/vm-pgtable.h"

static int handle_pte_fault(struct vm_area_struct *vma, unsigned long address,
			    unsigned int flags, pmd_t *pmd)
{
	return 0;
}

int handle_lego_mm_fault(struct vm_area_struct *vma, unsigned long address,
			 unsigned int flags)
{
	struct lego_mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	pgd = lego_pgd_offset(mm, address);
	pud = lego_pud_alloc(mm, pgd, address);
	if (!pud)
		return VM_FAULT_OOM;
	pmd = lego_pmd_alloc(mm, pud, address);
	if (!pmd)
		return VM_FAULT_OOM;

	return handle_pte_fault(vma, address, flags, pmd);
}
