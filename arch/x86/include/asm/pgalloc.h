/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_PGALLOC_H
#define _ASM_X86_PGALLOC_H

#include <asm/page.h>
#include <asm/pgtable.h>

struct mm_struct;

static inline void pmd_populate_kernel(struct mm_struct *mm,
				       pmd_t *pmd, pte_t *pte)
{
	pmd_set(pmd, __pmd(__pa(pte) | _PAGE_TABLE));
}

/*
 * Currently stuck as a macro due to indirect forward reference to
 * linux/mmzone.h's __section_mem_map_addr() definition:
 */
#define pmd_page(pmd)		\
	pfn_to_page((pmd_val(pmd) & pmd_pfn_mask(pmd)) >> PAGE_SHIFT)

#define pmd_pgtable(pmd) pmd_page(pmd)

static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	pud_set(pud, __pud(_PAGE_TABLE | __pa(pmd)));
}

static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
	pgd_set(pgd, __pgd(_PAGE_TABLE | __pa(pud)));
}

pte_t *pte_alloc_one_kernel(struct mm_struct *, unsigned long);
struct page *pte_alloc_one(struct mm_struct *, unsigned long);

void pte_free_kernel(struct mm_struct *mm, pte_t *pte);
void pte_free(struct mm_struct *mm, struct page *pte);

pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr);
pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr);

void pmd_free(struct mm_struct *mm, pmd_t *pmd);
void pud_free(struct mm_struct *mm, pud_t *pud);

/*
 * Allocate and free page tables.
 */
pgd_t *pgd_alloc(struct mm_struct *);
void pgd_free(struct mm_struct *mm, pgd_t *pgd);

#endif /* _ASM_X86_PGALLOC_H */
