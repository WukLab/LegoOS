/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/comp_memory.h>

#include <memory/include/vm.h>
#include <memory/include/vm-pgtable.h>

#define PGALLOC_GFP	(GFP_KERNEL | __GFP_ZERO)

static inline pud_t *lego_pud_alloc_one(void)
{
	return (pud_t *)__get_free_page(PGALLOC_GFP);
}

static inline pmd_t *lego_pmd_alloc_one(void)
{
	return (pmd_t *)__get_free_page(PGALLOC_GFP);
}

static inline pte_t *lego_pte_alloc_one(void)
{
	return (pte_t *)__get_free_page(PGALLOC_GFP);
}

static inline void lego_pud_free(pud_t *pud)
{
	BUG_ON((unsigned long)pud & (PAGE_SIZE-1));
	free_page((unsigned long)pud);
}

static inline void lego_pmd_free(pmd_t *pmd)
{
	BUG_ON((unsigned long)pmd & (PAGE_SIZE-1));
	free_page((unsigned long)pmd);
}

static inline void lego_pte_free(pte_t *pte)
{
	BUG_ON((unsigned long)pte & (PAGE_SIZE-1));
	free_page((unsigned long)pte);
}

static inline void lego_pmd_populate(pmd_t *pmd, pte_t *pte)
{
	pmd_set(pmd, __pmd(_PAGE_TABLE | __pa(pte)));
}

static inline void lego_pud_populate(pud_t *pud, pmd_t *pmd)
{
	pud_set(pud, __pud(_PAGE_TABLE | __pa(pmd)));
}

static inline void lego_pgd_populate(pgd_t *pgd, pud_t *pud)
{
	pgd_set(pgd, __pgd(_PAGE_TABLE | __pa(pud)));
}

/*
 * Allocate page upper directory.
 * We've already handled the fast-path in-line.
 */
int __lego_pud_alloc(struct lego_mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	pud_t *new = lego_pud_alloc_one();
	if (!new)
		return -ENOMEM;

	barrier();

	spin_lock(&mm->page_table_lock);
	if (pgd_present(*pgd))
		 /* Another has populated it */
		lego_pud_free(new);
	else
		lego_pgd_populate(pgd, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}

int __lego_pmd_alloc(struct lego_mm_struct *mm, pud_t *pud, unsigned long address)
{
	pmd_t *new = lego_pmd_alloc_one();
	if (!new)
		return -ENOMEM;

	barrier();

	spin_lock(&mm->page_table_lock);
	if (pud_present(*pud))
		 /* Another has populated it */
		lego_pmd_free(new);
	else
		lego_pud_populate(pud, new);
	spin_unlock(&mm->page_table_lock);
	return 0;
}

int __lego_pte_alloc(struct lego_mm_struct *mm, pmd_t *pmd, unsigned long address)
{
	pte_t *new = lego_pte_alloc_one();
	if (!new)
		return -ENOMEM;

	barrier();
	spin_lock(&mm->page_table_lock);
	if (pmd_present(*pmd))
		 /* Another has populated it */
		lego_pte_free(new);
	else {
		atomic_long_inc(&mm->nr_ptes);
		lego_pmd_populate(pmd, new);
	} spin_unlock(&mm->page_table_lock);
	return 0;
}

void free_pgd_range(struct lego_mm_struct *mm,
		    unsigned long start, unsigned long end)
{

}

unsigned long move_page_tables(struct vm_area_struct *vma,
		unsigned long old_addr, struct vm_area_struct *new_vma,
		unsigned long new_addr, unsigned long len,
		bool need_rmap_locks)
{
	return 0;
}
