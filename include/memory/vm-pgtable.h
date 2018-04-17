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
#include <memory/task.h>

/*
 * lego_pxd_index (pxd_array[index])
 * Given the address, return the index into the page table array
 */
static inline unsigned long lego_pgd_index(unsigned long address)
{
	return (address >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1);
}

static inline unsigned long lego_pud_index(unsigned long address)
{
	return (address >> PUD_SHIFT) & (PTRS_PER_PUD - 1);
}

static inline unsigned long lego_pmd_index(unsigned long address)
{
	return (address >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
}

static inline unsigned long lego_pte_index(unsigned long address)
{
	return (address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
}

/*
 * lego_pxd_page_vaddr
 * Given a page table entry, return the virtual address of the page
 * that this page table entry points to. (We saved kernel virtual address
 * into the page table entry).
 *
 * HACK!!! This set of functions are different from the normal ones.
 * These use PTE_VFN_MASK, instead of PFN_PFN_MASK.
 */
static inline unsigned long lego_pgd_page_vaddr(pgd_t pgd)
{
	return (unsigned long)((unsigned long)pgd_val(pgd) & PTE_VFN_MASK);
}

static inline unsigned long lego_pud_page_vaddr(pud_t pud)
{
	return (unsigned long)((unsigned long)pud_val(pud) & PTE_VFN_MASK);
}

static inline unsigned long lego_pmd_page_vaddr(pmd_t pmd)
{
	return (unsigned long)((unsigned long)pmd_val(pmd) & PTE_VFN_MASK);
}

/*
 * lego_pxd_offset
 * Return the corresponding page table entry that @address belongs to.
 */
static inline pgd_t *lego_pgd_offset(struct lego_mm_struct *mm, unsigned long address)
{
	return mm->pgd + lego_pgd_index(address);
}

static inline pud_t *lego_pud_offset(pgd_t *pgd, unsigned long address)
{
	return (pud_t *)lego_pgd_page_vaddr(*pgd) + lego_pud_index(address);
}

static inline pmd_t *lego_pmd_offset(pud_t *pud, unsigned long address)
{
	return (pmd_t *)lego_pud_page_vaddr(*pud) + lego_pmd_index(address);
}

static inline pte_t *lego_pte_offset(pmd_t *pmd, unsigned long address)
{
	return (pte_t *)lego_pmd_page_vaddr(*pmd) + lego_pte_index(address);
}

int __lego_pud_alloc(struct lego_mm_struct *mm, pgd_t *pgd, unsigned long address);
int __lego_pmd_alloc(struct lego_mm_struct *mm, pud_t *pud, unsigned long address);
int __lego_pte_alloc(struct lego_mm_struct *mm, pmd_t *pmd, unsigned long address);

static inline pud_t *
lego_pud_alloc(struct lego_mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	return (unlikely(pgd_none(*pgd)) && __lego_pud_alloc(mm, pgd, address))?
		NULL : lego_pud_offset(pgd, address);
}

static inline pmd_t *
lego_pmd_alloc(struct lego_mm_struct *mm, pud_t *pud, unsigned long address)
{
	return (unlikely(pud_none(*pud)) && __lego_pmd_alloc(mm, pud, address))?
		NULL : lego_pmd_offset(pud, address);
}

static inline pte_t *
lego_pte_alloc(struct lego_mm_struct *mm, pmd_t *pmd, unsigned long address)
{
	return (unlikely(pmd_none(*pmd) && __lego_pte_alloc(mm, pmd, address))?
		NULL : lego_pte_offset(pmd, address));
}

static inline pte_t lego_vfn_pte(unsigned long vfn, pgprot_t pgprot)
{
	return __pte(vfn << PAGE_SHIFT | pgprot_val(pgprot));
}

/* Returns the page that is used as the PTE pgtable */
static inline struct page *lego_pmd_page(pmd_t pmd)
{
	return virt_to_page((void *)lego_pmd_page_vaddr(pmd));
}

/*
 * Per PTE page lock
 */
#if USE_SPLIT_PTE_PTLOCKS
static inline spinlock_t *lego_ptlock_ptr(struct page *page)
{
	return &page->ptl;
}

static inline spinlock_t *lego_pte_lockptr(struct lego_mm_struct *mm, pmd_t *pmd)
{
	return lego_ptlock_ptr(lego_pmd_page(*pmd));
}

static inline bool lego_ptlock_init(struct page *page)
{
	spin_lock_init(lego_ptlock_ptr(page));
	return true;
}

static inline void lego_pte_lock_deinit(struct page *page)
{
}
#else
/*
 * We use mm->page_table_lock to guard all pagetable pages of the mm.
 */
static inline spinlock_t *lego_pte_lockptr(struct lego_mm_struct *mm, pmd_t *pmd)
{
	return &mm->lego_page_table_lock;
}
static inline bool lego_ptlock_init(struct page *page) { return true; }
static inline void lego_pte_lock_deinit(struct page *page) {}
#endif /* USE_SPLIT_PTE_PTLOCKS */

/*
 * Per PMD page lock
 * lego_pmd_to_page returns the page that is used as the PMD page
 */
#if USE_SPLIT_PMD_PTLOCKS
static inline struct page *lego_pmd_to_page(pmd_t *pmd)
{
	unsigned long mask = ~(PTRS_PER_PMD * sizeof(pmd_t) - 1);
	return virt_to_page((void *)((unsigned long) pmd & mask));
}

static inline spinlock_t *lego_pmd_lockptr(struct lego_mm_struct *mm, pmd_t *pmd)
{
	return lego_ptlock_ptr(lego_pmd_to_page(pmd));
}

static inline bool lego_pgtable_pmd_page_ctor(struct page *page)
{
	return lego_ptlock_init(page);
}

static inline void lego_pgtable_pmd_page_dtor(struct page *page)
{
}
#else
/*
 * We use mm->page_table_lock to guard all pagetable pages of the mm.
 */
static inline spinlock_t *lego_pmd_lockptr(struct lego_mm_struct *mm, pmd_t *pmd)
{
	return &mm->lego_page_table_lock;
}
static inline bool lego_pgtable_pmd_page_ctor(struct page *page) { return true; }
static inline void lego_pgtable_pmd_page_dtor(struct page *page) {}
#endif

static inline spinlock_t *lego_pmd_lock(struct lego_mm_struct *mm, pmd_t *pmd)
{
	spinlock_t *ptl = lego_pmd_lockptr(mm, pmd);
	spin_lock(ptl);
	return ptl;
}

#define lego_pte_offset_lock(mm, pmd, address, ptlp)	\
({							\
	spinlock_t *__ptl = lego_pte_lockptr(mm, pmd);	\
	pte_t *__pte = lego_pte_offset(pmd, address);	\
	*(ptlp) = __ptl;				\
	spin_lock(__ptl);				\
	__pte;						\
})

#define lego_pte_unlock(pte, ptl)			\
do {							\
	spin_unlock(ptl);				\
} while (0)

#endif /* _LEGO_MEMORY_VM_PGTABLE_H_ */
