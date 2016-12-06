#ifndef _ASM_X86_PGALLOC_H
#define _ASM_X86_PGALLOC_H

#include <asm/pgtable.h>

static inline void pmd_populate_kernel(struct mm_struct *mm,
				       pmd_t *pmd, pte_t *pte)
{
	pmd_set(pmd, __pmd(__pa(pte) | _PAGE_TABLE));
}

#define pmd_pgtable(pmd) pmd_page(pmd)

#ifdef CONFIG_X86_PAE
extern void pud_populate(struct mm_struct *mm, pud_t *pudp, pmd_t *pmd);
#else	/* !CONFIG_X86_PAE */
static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	pud_set(pud, __pud(_PAGE_TABLE | __pa(pmd)));
}
#endif	/* CONFIG_X86_PAE */

static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
	pgd_set(pgd, __pgd(_PAGE_TABLE | __pa(pud)));
}

#endif /* _ASM_X86_PGALLOC_H */
