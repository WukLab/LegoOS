/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_PGTABLE_H_
#define _ASM_X86_PGTABLE_H_

#include <asm/page.h>
#include <asm/pgtable_types.h>

#ifndef __ASSEMBLY__

#include <asm/asm.h>
#include <asm/cmpxchg.h>
#include <lego/spinlock.h>

extern pud_t level3_kernel_pgt[512];
extern pud_t level3_ident_pgt[512];
extern pmd_t level2_kernel_pgt[512];
extern pmd_t level2_fixmap_pgt[512];
extern pmd_t level2_ident_pgt[512];
extern pte_t level1_fixmap_pgt[512];
extern pgd_t init_level4_pgt[];

#define swapper_pg_dir init_level4_pgt

extern spinlock_t pgd_lock;
extern struct list_head pgd_list;

#endif /* !__ASSEMBLY__ */

/*
 * the pgd page can be thought of an array like this: pgd_t[PTRS_PER_PGD]
 *
 * this macro returns the index of the entry in the pgd page which would
 * control the given virtual address
 */
#define pgd_index(address) (((address) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))

/*
 * pgd_offset() returns a (pgd_t *)
 * pgd_index() is used get the offset into the pgd page's array of pgd_t's;
 */
#define pgd_offset(mm, address) ((mm)->pgd + pgd_index((address)))

/*
 * a shortcut which implies the use of the kernel's pgd, instead
 * of a process's
 */
#define pgd_offset_k(address) pgd_offset(&init_mm, (address))

#define KERNEL_PGD_BOUNDARY	pgd_index(PAGE_OFFSET)
#define KERNEL_PGD_PTRS		(PTRS_PER_PGD - KERNEL_PGD_BOUNDARY)

#ifndef __ASSEMBLY__

/*
 * The following only work if pte_present() is true.
 * Undefined behaviour if not..
 */
static inline int pte_dirty(pte_t pte)
{
	return pte_flags(pte) & _PAGE_DIRTY;
}

static inline int pte_young(pte_t pte)
{
	return pte_flags(pte) & _PAGE_ACCESSED;
}

static inline int pmd_dirty(pmd_t pmd)
{
	return pmd_flags(pmd) & _PAGE_DIRTY;
}

static inline int pmd_young(pmd_t pmd)
{
	return pmd_flags(pmd) & _PAGE_ACCESSED;
}

static inline int pte_write(pte_t pte)
{
	return pte_flags(pte) & _PAGE_RW;
}

static inline int pte_huge(pte_t pte)
{
	return pte_flags(pte) & _PAGE_PSE;
}

static inline int pte_global(pte_t pte)
{
	return pte_flags(pte) & _PAGE_GLOBAL;
}

static inline int pte_exec(pte_t pte)
{
	return !(pte_flags(pte) & _PAGE_NX);
}

static inline int pte_special(pte_t pte)
{
	return pte_flags(pte) & _PAGE_SPECIAL;
}

static inline int pte_zerofill(pte_t pte)
{
	return pte_flags(pte) & _PAGE_ZEROFILL;
}

static inline int pte_zerofill_locked(pte_t pte)
{
	return pte_flags(pte) & _PAGE_ZEROFILL_LOCKED;
}

static inline unsigned long pte_pfn(pte_t pte)
{
	return (pte_val(pte) & PTE_PFN_MASK) >> PAGE_SHIFT;
}

static inline unsigned long pmd_pfn(pmd_t pmd)
{
	return (pmd_val(pmd) & pmd_pfn_mask(pmd)) >> PAGE_SHIFT;
}

static inline unsigned long pud_pfn(pud_t pud)
{
	return (pud_val(pud) & pud_pfn_mask(pud)) >> PAGE_SHIFT;
}

#define pte_page(pte)	pfn_to_page(pte_pfn(pte))

static inline int pmd_large(pmd_t pte)
{
	return pmd_flags(pte) & _PAGE_PSE;
}

/* to find an entry in a page-table-directory. */
static inline unsigned long pud_index(unsigned long address)
{
	return (address >> PUD_SHIFT) & (PTRS_PER_PUD - 1);
}

static inline int pud_large(pud_t pud)
{
	return (pud_val(pud) & (_PAGE_PSE | _PAGE_PRESENT)) ==
		(_PAGE_PSE | _PAGE_PRESENT);
}

static inline void pte_set(pte_t *ptep, pte_t pte)
{
	*ptep = pte;
}

static inline void pte_clear(pte_t *ptep)
{
	*ptep = __pte(0);
}

static inline void pmd_set(pmd_t *pmdp, pmd_t pmd)
{
	*pmdp = pmd;
}

static inline void pmd_clear(pmd_t *pmdp)
{
	*pmdp = __pmd(0);
}

static inline void pud_set(pud_t *pudp, pud_t pud)
{
	*pudp = pud;
}

static inline void pud_clear(pud_t *pudp)
{
	*pudp = __pud(0);
}

static inline void pgd_set(pgd_t *pgdp, pgd_t pgd)
{
	*pgdp = pgd;
}

static inline void pgd_clear(pgd_t *pgdp)
{
	*pgdp = __pgd(0);
}

static inline pte_t pfn_pte(unsigned long page_nr, pgprot_t pgprot)
{
	return __pte(((phys_addr_t)page_nr << PAGE_SHIFT) |
		     massage_pgprot(pgprot));
}

static inline pmd_t pfn_pmd(unsigned long page_nr, pgprot_t pgprot)
{
	return __pmd(((phys_addr_t)page_nr << PAGE_SHIFT) |
		     massage_pgprot(pgprot));
}

static inline pte_t pte_set_flags(pte_t pte, pteval_t set)
{
	pteval_t v = native_pte_val(pte);

	return native_make_pte(v | set);
}

static inline pte_t pte_clear_flags(pte_t pte, pteval_t clear)
{
	pteval_t v = native_pte_val(pte);

	return native_make_pte(v & ~clear);
}

static inline pte_t pte_mkclean(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_DIRTY);
}

static inline pte_t pte_mkold(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_ACCESSED);
}

static inline pte_t pte_wrprotect(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_RW);
}

static inline pte_t pte_mkexec(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_NX);
}

static inline pte_t pte_mkdirty(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_DIRTY | _PAGE_SOFT_DIRTY);
}

static inline pte_t pte_mkyoung(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_ACCESSED);
}

static inline pte_t pte_mkwrite(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_RW);
}

static inline pte_t pte_mkhuge(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_PSE);
}

static inline pte_t pte_clrhuge(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_PSE);
}

static inline pte_t pte_mkglobal(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_GLOBAL);
}

static inline pte_t pte_clrglobal(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_GLOBAL);
}

static inline pte_t pte_mkspecial(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_SPECIAL);
}

static inline pte_t pte_mkzerofill(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_ZEROFILL);
}

static inline pte_t pte_mkzerofill_locked(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_ZEROFILL_LOCKED);
}

static inline pmd_t pmd_set_flags(pmd_t pmd, pmdval_t set)
{
	pmdval_t v = native_pmd_val(pmd);

	return __pmd(v | set);
}

static inline pmd_t pmd_clear_flags(pmd_t pmd, pmdval_t clear)
{
	pmdval_t v = native_pmd_val(pmd);

	return __pmd(v & ~clear);
}

static inline pmd_t pmd_mkold(pmd_t pmd)
{
	return pmd_clear_flags(pmd, _PAGE_ACCESSED);
}

static inline pmd_t pmd_mkclean(pmd_t pmd)
{
	return pmd_clear_flags(pmd, _PAGE_DIRTY);
}

static inline pmd_t pmd_wrprotect(pmd_t pmd)
{
	return pmd_clear_flags(pmd, _PAGE_RW);
}

static inline pmd_t pmd_mkdirty(pmd_t pmd)
{
	return pmd_set_flags(pmd, _PAGE_DIRTY | _PAGE_SOFT_DIRTY);
}

static inline pmd_t pmd_mkhuge(pmd_t pmd)
{
	return pmd_set_flags(pmd, _PAGE_PSE);
}

static inline pmd_t pmd_mkyoung(pmd_t pmd)
{
	return pmd_set_flags(pmd, _PAGE_ACCESSED);
}

static inline pmd_t pmd_mkwrite(pmd_t pmd)
{
	return pmd_set_flags(pmd, _PAGE_RW);
}

static inline pmd_t pmd_mknotpresent(pmd_t pmd)
{
	return pmd_clear_flags(pmd, _PAGE_PRESENT | _PAGE_PROTNONE);
}

#define pte_pgprot(x) __pgprot(pte_flags(x))
#define pmd_pgprot(x) __pgprot(pmd_flags(x))
#define pud_pgprot(x) __pgprot(pud_flags(x))

#define canon_pgprot(p) __pgprot(massage_pgprot(p))

static inline int pte_none(pte_t pte)
{
	return !(pte.pte & ~(_PAGE_KNL_ERRATUM_MASK));
}

static inline int pte_same(pte_t a, pte_t b)
{
	return a.pte == b.pte;
}

static inline int pte_present(pte_t a)
{
	return pte_flags(a) & (_PAGE_PRESENT | _PAGE_PROTNONE);
}

static inline int pmd_present(pmd_t pmd)
{
	/*
	 * Checking for _PAGE_PSE is needed too because
	 * split_huge_page will temporarily clear the present bit (but
	 * the _PAGE_PSE flag will remain set at all times while the
	 * _PAGE_PRESENT bit is clear).
	 */
	return pmd_flags(pmd) & (_PAGE_PRESENT | _PAGE_PROTNONE | _PAGE_PSE);
}

static inline int pmd_none(pmd_t pmd)
{
	/* Only check low word on 32-bit platforms, since it might be
	   out of sync with upper half. */
	unsigned long val = native_pmd_val(pmd);
	return (val & ~_PAGE_KNL_ERRATUM_MASK) == 0;
}

static inline int pmd_bad(pmd_t pmd)
{
	return (pmd_flags(pmd) & ~_PAGE_USER) != _KERNPG_TABLE;
}

/*
 * the pmd page can be thought of an array like this: pmd_t[PTRS_PER_PMD]
 *
 * this macro returns the index of the entry in the pmd page which would
 * control the given virtual address
 */
static inline unsigned long pmd_index(unsigned long address)
{
	return (address >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
}

/*
 * the pte page can be thought of an array like this: pte_t[PTRS_PER_PTE]
 *
 * this function returns the index of the entry in the pte page which would
 * control the given virtual address
 */
static inline unsigned long pte_index(unsigned long address)
{
	return (address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
}

static inline int pud_none(pud_t pud)
{
	return (native_pud_val(pud) & ~(_PAGE_KNL_ERRATUM_MASK)) == 0;
}

static inline int pud_present(pud_t pud)
{
	return pud_flags(pud) & _PAGE_PRESENT;
}

static inline int pud_bad(pud_t pud)
{
	return (pud_flags(pud) & ~(_KERNPG_TABLE | _PAGE_USER)) != 0;
}

static inline int pgd_present(pgd_t pgd)
{
	return pgd_flags(pgd) & _PAGE_PRESENT;
}

static inline int pgd_bad(pgd_t pgd)
{
	return (pgd_flags(pgd) & ~_PAGE_USER) != _KERNPG_TABLE;
}

static inline int pgd_none(pgd_t pgd)
{
	/*
	 * There is no need to do a workaround for the KNL stray
	 * A/D bit erratum here.  PGDs only point to page tables
	 * except on 32-bit non-PAE which is not supported on
	 * KNL.
	 */
	return !native_pgd_val(pgd);
}

static inline unsigned long pgd_page_vaddr(pgd_t pgd)
{
	return (unsigned long)__va((unsigned long)pgd_val(pgd) & PTE_PFN_MASK);
}

static inline unsigned long pmd_page_vaddr(pmd_t pmd)
{
	return (unsigned long)__va(pmd_val(pmd) & pmd_pfn_mask(pmd));
}

static inline unsigned long pud_page_vaddr(pud_t pud)
{
	return (unsigned long)__va(pud_val(pud) & pud_pfn_mask(pud));
}

static inline pud_t *pud_offset(pgd_t *pgd, unsigned long address)
{
	return (pud_t *)pgd_page_vaddr(*pgd) + pud_index(address);
}

/* Find an entry in the second-level page table.. */
static inline pmd_t *pmd_offset(pud_t *pud, unsigned long address)
{
	return (pmd_t *)pud_page_vaddr(*pud) + pmd_index(address);
}

static inline pte_t *pte_offset(pmd_t *pmd, unsigned long address)
{
	return (pte_t *)pmd_page_vaddr(*pmd) + pte_index(address);
}

static inline pte_t *pte_offset_kernel(pmd_t *pmd, unsigned long address)
{
	return (pte_t *)pmd_page_vaddr(*pmd) + pte_index(address);
}

/*
 * Conversion functions: convert a page and protection to a page entry,
 * and a page entry and page directory to the page they refer to.
 */
#define mk_pte(page, pgprot)   pfn_pte(page_to_pfn(page), (pgprot))

static inline void load_cr3(pgd_t *pgdir)
{
	write_cr3(__pa(pgdir));
}

/*
 * When walking page tables, get the address of the next boundary,
 * or the end address of the range if that comes earlier.  Although no
 * vma end wraps to 0, rounded up __boundary may wrap to 0 throughout.
 */

#define pgd_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PGDIR_SIZE) & PGDIR_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})

#define pud_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PUD_SIZE) & PUD_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})

#define pmd_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PMD_SIZE) & PMD_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})

extern void __init init_mem_mapping(void);

/*
 * clone_pgd_range(pgd_t *dst, pgd_t *src, int count);
 *
 *  dst - pointer to pgd range anwhere on a pgd page
 *  src - ""
 *  count - the number of pgds to copy.
 *
 * dst and src can be on the same page, but the range must not overlap,
 * and must not cross a page boundary.
 */
static inline void clone_pgd_range(pgd_t *dst, pgd_t *src, int count)
{
       memcpy(dst, src, count * sizeof(pgd_t));
}

/* local pte updates need not use xchg for locking */
static inline pte_t native_local_ptep_get_and_clear(pte_t *ptep)
{
	pte_t res = *ptep;

	/* Pure native function needs no input for mm, addr */
	pte_clear(ptep);
	return res;
}

#ifdef CONFIG_SMP
static inline pte_t native_ptep_get_and_clear(pte_t *xp)
{
	return __pte(xchg(&xp->pte, 0));
}
#else
#define native_ptep_get_and_clear(xp) native_local_ptep_get_and_clear(xp)
#endif

static inline pte_t ptep_get_and_clear(unsigned long addr, pte_t *ptep)
{
	pte_t pte = native_ptep_get_and_clear(ptep);
	return pte;
}

#define pte_ERROR(e)					\
	pr_err("%s:%d: bad pte %p(%016lx)\n",		\
	       __FILE__, __LINE__, &(e), pte_val(e))
#define pmd_ERROR(e)					\
	pr_err("%s:%d: bad pmd %p(%016lx)\n",		\
	       __FILE__, __LINE__, &(e), pmd_val(e))
#define pud_ERROR(e)					\
	pr_err("%s:%d: bad pud %p(%016lx)\n",		\
	       __FILE__, __LINE__, &(e), pud_val(e))
#define pgd_ERROR(e)					\
	pr_err("%s:%d: bad pgd %p(%016lx)\n",		\
	       __FILE__, __LINE__, &(e), pgd_val(e))

/*
 * If a p?d_bad entry is found while walking page tables, report
 * the error, before resetting entry to p?d_none.  Usually (but
 * very seldom) called out from the p?d_none_or_clear_bad macros.
 */

static inline void pgd_clear_bad(pgd_t *pgd)
{
	pgd_ERROR(*pgd);
	pgd_clear(pgd);
}

static inline void pud_clear_bad(pud_t *pud)
{
	pud_ERROR(*pud);
	pud_clear(pud);
}

static inline void pmd_clear_bad(pmd_t *pmd)
{
	pmd_ERROR(*pmd);
	pmd_clear(pmd);
}

static inline int pgd_none_or_clear_bad(pgd_t *pgd)
{
	if (pgd_none(*pgd))
		return 1;
	if (unlikely(pgd_bad(*pgd))) {
		pgd_clear_bad(pgd);
		return 1;
	}
	return 0;
}

static inline int pud_none_or_clear_bad(pud_t *pud)
{
	if (pud_none(*pud))
		return 1;
	if (unlikely(pud_bad(*pud))) {
		pud_clear_bad(pud);
		return 1;
	}
	return 0;
}

static inline int pmd_none_or_clear_bad(pmd_t *pmd)
{
	if (pmd_none(*pmd))
		return 1;
	if (unlikely(pmd_bad(*pmd))) {
		pmd_clear_bad(pmd);
		return 1;
	}
	return 0;
}

static inline void ptep_clear_zerofill_locked(pte_t *ptep)
{
	clear_bit(_PAGE_BIT_ZEROFILL_LOCKED, (unsigned long *)&ptep->pte);
}

static inline void ptep_clear_zerofill(pte_t *ptep)
{
	clear_bit(_PAGE_BIT_ZEROFILL, (unsigned long *)&ptep->pte);
}

static inline void ptep_set_zerofill_locked(pte_t *ptep)
{
	set_bit(_PAGE_BIT_ZEROFILL_LOCKED, (unsigned long *)&ptep->pte);
}

static inline void ptep_set_zerofill(pte_t *ptep)
{
	set_bit(_PAGE_BIT_ZEROFILL, (unsigned long *)&ptep->pte);
}

static inline void ptep_set_wrprotect(pte_t *ptep)
{
	clear_bit(_PAGE_BIT_RW, (unsigned long *)&ptep->pte);
}

static inline pte_t ptep_get_and_clear_full(pte_t *ptep)
{
	/*
	 * Full address destruction in progress; Does not
	 * care about updates and native needs no locking
	 */
	return native_local_ptep_get_and_clear(ptep);
}

static inline int ptep_test_and_clear_young(pte_t *ptep)
{
	int ret = 0;

	if (pte_young(*ptep))
		ret = test_and_clear_bit(_PAGE_BIT_ACCESSED,
					 (unsigned long *)&ptep->pte);
	return ret;
}

static inline int ptep_clear_flush_young(pte_t *ptep)
{
	/*
	 * On x86 CPUs, clearing the accessed bit without a TLB flush
	 * doesn't cause data corruption. [ It could cause incorrect
	 * page aging and the (mistaken) reclaim of hot pages, but the
	 * chance of that should be relatively low. ]
	 *
	 * So as a performance optimization don't flush the TLB when
	 * clearing the accessed bit, it will eventually be flushed by
	 * a context switch or a VM operation anyway. [ In the rare
	 * event of it not getting flushed for a long time the delay
	 * shouldn't really matter because there's no real memory
	 * pressure for swapout to react to. ]
	 */
	return ptep_test_and_clear_young(ptep);
}

#define flush_tlb_fix_spurious_fault(vma, address) do { } while (0)

void ptdump_walk_pgd_level(pgd_t *pgd);
int __init pt_dump_init(void);

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_PGTABLE_H_ */
