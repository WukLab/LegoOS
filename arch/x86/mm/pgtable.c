/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include <lego/mm.h>
#include <lego/vmstat.h>
#include <lego/kernel.h>

static inline bool pgtable_page_ctor(struct page *page)
{
	if (!ptlock_init(page))
		return false;
	inc_zone_page_state(page, NR_PAGETABLE);
	return true;
}

static inline void pgtable_page_dtor(struct page *page)
{
	pte_lock_deinit(page);
	dec_zone_page_state(page, NR_PAGETABLE);
}

#define PGALLOC_GFP	(GFP_KERNEL | __GFP_ZERO)

pte_t *pte_alloc_one_kernel(struct mm_struct *mm, unsigned long address)
{
	return (pte_t *)__get_free_page(PGALLOC_GFP);
}

struct page *pte_alloc_one(struct mm_struct *mm, unsigned long address)
{
	struct page *pte;

	pte = alloc_pages(PGALLOC_GFP, 0);
	if (!pte)
		return NULL;
	if (!pgtable_page_ctor(pte)) {
		__free_page(pte);
		return NULL;
	}
	return pte;
}

pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	return (pud_t *)__get_free_page(PGALLOC_GFP);
}

pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	struct page *page;

	page = alloc_pages(PGALLOC_GFP, 0);
	if (!page)
		return NULL;
	if (!pgtable_pmd_page_ctor(page)) {
		__free_pages(page, 0);
		return NULL;
	}
	return (pmd_t *)page_address(page);
}

void pte_free_kernel(struct mm_struct *mm, pte_t *pte)
{
	BUG_ON((unsigned long)pte & (PAGE_SIZE-1));
	free_page((unsigned long)pte);
}

void pte_free(struct mm_struct *mm, struct page *pte)
{
	pgtable_page_dtor(pte);
	__free_page(pte);
}

void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	BUG_ON((unsigned long)pmd & (PAGE_SIZE-1));
	pgtable_pmd_page_dtor(virt_to_page(pmd));
	free_page((unsigned long)pmd);
}

void pud_free(struct mm_struct *mm, pud_t *pud)
{
	BUG_ON((unsigned long)pud & (PAGE_SIZE-1));
	free_page((unsigned long)pud);
}

/*
 * A list of pages that are used as pgd
 */
LIST_HEAD(pgd_list);
DEFINE_SPINLOCK(pgd_lock);

static inline void pgd_list_add(pgd_t *pgd)
{
	struct page *page = virt_to_page(pgd);

	list_add(&page->lru, &pgd_list);
}

static inline void pgd_list_del(pgd_t *pgd)
{
	struct page *page = virt_to_page(pgd);

	list_del(&page->lru);
}

static void pgd_set_mm(pgd_t *pgd, struct mm_struct *mm)
{
	BUILD_BUG_ON(sizeof(virt_to_page(pgd)->index) < sizeof(mm));
	virt_to_page(pgd)->index = (pgoff_t)mm;
}

struct mm_struct *pgd_page_get_mm(struct page *page)
{
	return (struct mm_struct *)page->index;
}

pgd_t *pgd_alloc(struct mm_struct *mm)
{
	pgd_t *pgd;

	pgd = (pgd_t *)__get_free_page(PGALLOC_GFP);
	if (!pgd)
		return NULL;

	/*
	 * Copy the kernel identity mapping
	 * for all the forked processes..
	 *
	 * That is where user-kernel VA sapce split happens!
	 */
	spin_lock(&pgd_lock);
	clone_pgd_range(pgd + KERNEL_PGD_BOUNDARY,
			swapper_pg_dir + KERNEL_PGD_BOUNDARY,
			KERNEL_PGD_PTRS);

	pgd_set_mm(pgd, mm);
	pgd_list_add(pgd);
	spin_unlock(&pgd_lock);

	return pgd;
}

void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	spin_lock(&pgd_lock);
	pgd_list_del(pgd);
	spin_unlock(&pgd_lock);

	free_page((unsigned long)pgd);
}
