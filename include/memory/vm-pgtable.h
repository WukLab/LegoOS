/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * We reuse most of the pgtable operations here.
 * But do note that, we don't have to use traditional pgtable
 * here, since this pgtable is not used to do hardware page-walk.
 * Hashtable is also feasible.
 *
 * Well, maybe later the *real* memory component will also have
 * some hardaware table walker to walk through this one.
 */

#ifndef _LEGO_MEMORY_VM_PGTABLE_H_
#define _LEGO_MEMORY_VM_PGTABLE_H_

#include <asm/pgtable.h>
#include <lego/comp_memory.h>

#define lego_pgd_offset(mm, address) ((mm)->pgd + pgd_index((address)))

int __lego_pud_alloc(struct lego_mm_struct *mm, pgd_t *pgd, unsigned long address);
int __lego_pmd_alloc(struct lego_mm_struct *mm, pud_t *pud, unsigned long address);
int __lego_pte_alloc(struct lego_mm_struct *mm, pmd_t *pmd, unsigned long address);

static inline pud_t *
lego_pud_alloc(struct lego_mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	return (unlikely(pgd_none(*pgd)) && __lego_pud_alloc(mm, pgd, address))?
		NULL : pud_offset(pgd, address);
}

static inline pmd_t *
lego_pmd_alloc(struct lego_mm_struct *mm, pud_t *pud, unsigned long address)
{
	return (unlikely(pud_none(*pud)) && __lego_pmd_alloc(mm, pud, address))?
		NULL : pmd_offset(pud, address);
}

static inline pte_t *
lego_pte_alloc(struct lego_mm_struct *mm, pmd_t *pmd, unsigned long address)
{
	return (unlikely(pmd_none(*pmd) && __lego_pte_alloc(mm, pmd, address))?
		NULL : pte_offset(pmd, address));
}

static inline pte_t lego_vfn_pte(unsigned long vfn, pgprot_t pgprot)
{
	return __pte(vfn << PAGE_SHIFT | pgprot_val(pgprot));
}

/*
 * TODO: pgtable lock
 * We might want to use split locks for pte instead of using
 * mm->page_table_lock.
 */

/*
 * We use mm->page_table_lock to guard all pagetable pages of the mm.
 */
static inline spinlock_t *lego_pte_lockptr(struct lego_mm_struct *mm, pmd_t *pmd)
{
	return &mm->page_table_lock;
}

#define lego_pte_offset_lock(mm, pmd, address, ptlp)	\
({							\
	spinlock_t *__ptl = lego_pte_lockptr(mm, pmd);	\
	pte_t *__pte = pte_offset(pmd, address);	\
	*(ptlp) = __ptl;				\
	spin_lock(__ptl);				\
	__pte;						\
})

/*
 * XXX:
 * If per-pte is used, modify this code! 
 * Lock is wrong.
 */
#define lego_pte_alloc_lock(mm, pmd, address, ptlp)	\
({							\
	spinlock_t *__ptl = lego_pte_lockptr(mm, pmd);	\
	pte_t *__pte = lego_pte_alloc(mm, pmd, address);\
	if (__pte) {					\
		*(ptlp) = __ptl;			\
		spin_lock(__ptl);			\
	}						\
	__pte;						\
})

#define lego_pte_unlock(pte, ptl)			\
do {							\
	spin_unlock(ptl);				\
} while (0)

#endif /* _LEGO_MEMORY_VM_PGTABLE_H_ */
