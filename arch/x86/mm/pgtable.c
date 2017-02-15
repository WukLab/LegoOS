/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include <lego/mm.h>
#include <lego/kernel.h>

#define PGALLOC_GFP	(GFP_KERNEL | __GFP_ZERO)

pte_t *pte_alloc_one_kernel(struct mm_struct *mm, unsigned long address)
{
	return (pte_t *)__get_free_page(PGALLOC_GFP);
}

pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	return (pud_t *)__get_free_page(PGALLOC_GFP);
}

pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	return (pmd_t *)__get_free_page(PGALLOC_GFP);
}

struct page *pte_alloc_one(struct mm_struct *mm, unsigned long address)
{
	struct page *pte;

	pte = alloc_pages(PGALLOC_GFP, 0);
	if (!pte)
		return NULL;
/*
	if (!pgtable_page_ctor(pte)) {
		__free_page(pte);
		return NULL;
	}
*/
	return pte;
}

void pte_free_kernel(struct mm_struct *mm, pte_t *pte)
{
	BUG_ON((unsigned long)pte & (PAGE_SIZE-1));
	free_page((unsigned long)pte);
}

void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	BUG_ON((unsigned long)pmd & (PAGE_SIZE-1));
	free_page((unsigned long)pmd);
}

void pud_free(struct mm_struct *mm, pud_t *pud)
{
	BUG_ON((unsigned long)pud & (PAGE_SIZE-1));
	free_page((unsigned long)pud);
}

void pte_free(struct mm_struct *mm, struct page *pte)
{
	/* pgtable_page_dtor(pte); */
	__free_page(pte);
}
