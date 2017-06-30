/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgalloc.h>

#include <lego/mm.h>
#include <lego/bug.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/memblock.h>

#ifdef CONFIG_FLATMEM
struct pglist_data contig_page_data;
struct page *mem_map;
#endif

/*
 * Allocate page upper directory.
 * We've already handled the fast-path in-line.
 */
int __pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	pud_t *new = pud_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	barrier();

	spin_lock(&mm->page_table_lock);
	if (pgd_present(*pgd))		/* Another has populated it */
		pud_free(mm, new);
	else
		pgd_populate(mm, pgd, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}

/*
 * Allocate page middle directory.
 * We've already handled the fast-path in-line.
 */
int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	pmd_t *new = pmd_alloc_one(mm, address);
	if (!new)
		return -ENOMEM;

	barrier();

	spin_lock(&mm->page_table_lock);
	if (!pud_present(*pud))
		pud_populate(mm, pud, new);
	else	/* Another has populated it */
		pmd_free(mm, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}

int __pte_alloc(struct mm_struct *mm, pmd_t *pmd, unsigned long address)
{
	pte_t *new = pte_alloc_one_kernel(mm, address);
	if (!new)
		return -ENOMEM;

	barrier();
	spin_lock(&mm->page_table_lock);
	if (!pmd_present(*pmd))
		pmd_populate_kernel(mm, pmd, new);
	else	/* Another has populated it */
		pte_free_kernel(mm, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}

int __pte_alloc_kernel(pmd_t *pmd, unsigned long address)
{
	pte_t *new = pte_alloc_one_kernel(&init_mm, address);
	if (!new)
		return -ENOMEM;

	barrier();

	spin_lock(&init_mm.page_table_lock);
	if (likely(pmd_none(*pmd))) {	/* Has another populated it ? */
		pmd_populate_kernel(&init_mm, pmd, new);
		new = NULL;
	}
	spin_unlock(&init_mm.page_table_lock);
	if (new)
		pte_free_kernel(&init_mm, new);
	return 0;
}
