/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * x86-64's hardware page table definition
 */

#ifndef _ASM_X86_PGTABLE_TYPES_H_
#define _ASM_X86_PGTABLE_TYPES_H_

#include <lego/const.h>

#define _PAGE_BIT_PRESENT	0	/* is present */
#define _PAGE_BIT_RW		1	/* writeable */
#define _PAGE_BIT_USER		2	/* userspace addressable */
#define _PAGE_BIT_PWT		3	/* page write through */
#define _PAGE_BIT_PCD		4	/* page cache disabled */
#define _PAGE_BIT_ACCESSED	5	/* was accessed (raised by CPU) */
#define _PAGE_BIT_DIRTY		6	/* was written to (raised by CPU) */
#define _PAGE_BIT_PSE		7	/* 4 MB (or 2MB) page */
#define _PAGE_BIT_PAT		7	/* on 4KB pages */
#define _PAGE_BIT_GLOBAL	8	/* Global TLB entry PPro+ */
#define _PAGE_BIT_SOFTW1	9	/* available for programmer */
#define _PAGE_BIT_SOFTW2	10	/* " */
#define _PAGE_BIT_SOFTW3	11	/* " */
#define _PAGE_BIT_PAT_LARGE	12	/* On 2MB or 1GB pages */
#define _PAGE_BIT_SOFTW4	58	/* available for programmer */
#define _PAGE_BIT_PKEY_BIT0	59	/* Protection Keys, bit 1/4 */
#define _PAGE_BIT_PKEY_BIT1	60	/* Protection Keys, bit 2/4 */
#define _PAGE_BIT_PKEY_BIT2	61	/* Protection Keys, bit 3/4 */
#define _PAGE_BIT_PKEY_BIT3	62	/* Protection Keys, bit 4/4 */
#define _PAGE_BIT_NX		63	/* No execute: only valid after cpuid check */

#define _PAGE_BIT_SPECIAL		_PAGE_BIT_SOFTW1
#define _PAGE_BIT_DEVMAP		_PAGE_BIT_SOFTW4

#define _PAGE_BIT_ZEROFILL		_PAGE_BIT_SOFTW2 /* zero-fill pcache */
#define _PAGE_BIT_ZEROFILL_LOCKED	_PAGE_BIT_SOFTW3 /* zero-fill pcache async net in progress */

/* If _PAGE_BIT_PRESENT is clear, we use these: */
/* - if the user mapped it with PROT_NONE; pte_present gives true */
#define _PAGE_BIT_PROTNONE	_PAGE_BIT_GLOBAL

#define _PAGE_PRESENT	(_AT(pteval_t, 1) << _PAGE_BIT_PRESENT)
#define _PAGE_RW	(_AT(pteval_t, 1) << _PAGE_BIT_RW)
#define _PAGE_USER	(_AT(pteval_t, 1) << _PAGE_BIT_USER)
#define _PAGE_PWT	(_AT(pteval_t, 1) << _PAGE_BIT_PWT)
#define _PAGE_PCD	(_AT(pteval_t, 1) << _PAGE_BIT_PCD)
#define _PAGE_ACCESSED	(_AT(pteval_t, 1) << _PAGE_BIT_ACCESSED)
#define _PAGE_DIRTY	(_AT(pteval_t, 1) << _PAGE_BIT_DIRTY)
#define _PAGE_PSE	(_AT(pteval_t, 1) << _PAGE_BIT_PSE)
#define _PAGE_GLOBAL	(_AT(pteval_t, 1) << _PAGE_BIT_GLOBAL)
#define _PAGE_SOFTW1	(_AT(pteval_t, 1) << _PAGE_BIT_SOFTW1)
#define _PAGE_SOFTW2	(_AT(pteval_t, 1) << _PAGE_BIT_SOFTW2)
#define _PAGE_PAT	(_AT(pteval_t, 1) << _PAGE_BIT_PAT)
#define _PAGE_PAT_LARGE (_AT(pteval_t, 1) << _PAGE_BIT_PAT_LARGE)
#define _PAGE_SPECIAL	(_AT(pteval_t, 1) << _PAGE_BIT_SPECIAL)
#ifdef CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS
#define _PAGE_PKEY_BIT0	(_AT(pteval_t, 1) << _PAGE_BIT_PKEY_BIT0)
#define _PAGE_PKEY_BIT1	(_AT(pteval_t, 1) << _PAGE_BIT_PKEY_BIT1)
#define _PAGE_PKEY_BIT2	(_AT(pteval_t, 1) << _PAGE_BIT_PKEY_BIT2)
#define _PAGE_PKEY_BIT3	(_AT(pteval_t, 1) << _PAGE_BIT_PKEY_BIT3)
#else
#define _PAGE_PKEY_BIT0	(_AT(pteval_t, 0))
#define _PAGE_PKEY_BIT1	(_AT(pteval_t, 0))
#define _PAGE_PKEY_BIT2	(_AT(pteval_t, 0))
#define _PAGE_PKEY_BIT3	(_AT(pteval_t, 0))
#endif
#define __HAVE_ARCH_PTE_SPECIAL

#define _PAGE_ZEROFILL		(_AT(pteval_t, 1) << _PAGE_BIT_ZEROFILL)
#define _PAGE_ZEROFILL_LOCKED	(_AT(pteval_t, 1) << _PAGE_BIT_ZEROFILL_LOCKED)

#define _PAGE_PKEY_MASK (_PAGE_PKEY_BIT0 | \
			 _PAGE_PKEY_BIT1 | \
			 _PAGE_PKEY_BIT2 | \
			 _PAGE_PKEY_BIT3)

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
#define _PAGE_KNL_ERRATUM_MASK (_PAGE_DIRTY | _PAGE_ACCESSED)
#else
#define _PAGE_KNL_ERRATUM_MASK 0
#endif

/*
 * The same hidden bit is used by kmemcheck, but since kmemcheck
 * works on kernel pages while soft-dirty engine on user space,
 * they do not conflict with each other.
 */
#ifdef CONFIG_MEM_SOFT_DIRTY
#define _PAGE_SOFT_DIRTY	(_AT(pteval_t, 1) << _PAGE_BIT_SOFT_DIRTY)
#else
#define _PAGE_SOFT_DIRTY	(_AT(pteval_t, 0))
#endif

/*
 * Tracking soft dirty bit when a page goes to a swap is tricky.
 * We need a bit which can be stored in pte _and_ not conflict
 * with swap entry format. On x86 bits 6 and 7 are *not* involved
 * into swap entry computation, but bit 6 is used for nonlinear
 * file mapping, so we borrow bit 7 for soft dirty tracking.
 *
 * Please note that this bit must be treated as swap dirty page
 * mark if and only if the PTE has present bit clear!
 */
#ifdef CONFIG_MEM_SOFT_DIRTY
#define _PAGE_SWP_SOFT_DIRTY	_PAGE_PSE
#else
#define _PAGE_SWP_SOFT_DIRTY	(_AT(pteval_t, 0))
#endif

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
#define _PAGE_NX	(_AT(pteval_t, 1) << _PAGE_BIT_NX)
#define _PAGE_DEVMAP	(_AT(u64, 1) << _PAGE_BIT_DEVMAP)
#define __HAVE_ARCH_PTE_DEVMAP
#else
#define _PAGE_NX	(_AT(pteval_t, 0))
#define _PAGE_DEVMAP	(_AT(pteval_t, 0))
#endif

#define _PAGE_PROTNONE	(_AT(pteval_t, 1) << _PAGE_BIT_PROTNONE)

#define _PAGE_TABLE	(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER |	\
			 _PAGE_ACCESSED | _PAGE_DIRTY)
#define _KERNPG_TABLE	(_PAGE_PRESENT | _PAGE_RW |			\
			 _PAGE_ACCESSED | _PAGE_DIRTY)

/*
 * Set of bits not changed in pte_modify.  The pte's
 * protection key is treated like _PAGE_RW, for
 * instance, and is *not* included in this mask since
 * pte_modify() does modify it.
 */
#define _PAGE_CHG_MASK	(PTE_PFN_MASK | _PAGE_PCD | _PAGE_PWT |		\
			 _PAGE_SPECIAL | _PAGE_ACCESSED | _PAGE_DIRTY |	\
			 _PAGE_SOFT_DIRTY)
#define _HPAGE_CHG_MASK (_PAGE_CHG_MASK | _PAGE_PSE)

#define PAGE_NONE	__pgprot(_PAGE_PROTNONE | _PAGE_ACCESSED)
#define PAGE_SHARED	__pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_USER | \
				 _PAGE_ACCESSED | _PAGE_NX)

#define PAGE_SHARED_EXEC	__pgprot(_PAGE_PRESENT | _PAGE_RW |	\
					 _PAGE_USER | _PAGE_ACCESSED)
#define PAGE_COPY_NOEXEC	__pgprot(_PAGE_PRESENT | _PAGE_USER |	\
					 _PAGE_ACCESSED | _PAGE_NX)
#define PAGE_COPY_EXEC		__pgprot(_PAGE_PRESENT | _PAGE_USER |	\
					 _PAGE_ACCESSED)
#define PAGE_COPY		PAGE_COPY_NOEXEC
#define PAGE_READONLY		__pgprot(_PAGE_PRESENT | _PAGE_USER |	\
					 _PAGE_ACCESSED | _PAGE_NX)
#define PAGE_READONLY_EXEC	__pgprot(_PAGE_PRESENT | _PAGE_USER |	\
					 _PAGE_ACCESSED)

#define __PAGE_KERNEL_EXEC						\
	(_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED | _PAGE_GLOBAL)
#define __PAGE_KERNEL		(__PAGE_KERNEL_EXEC | _PAGE_NX)

#define __PAGE_KERNEL_RO		(__PAGE_KERNEL & ~_PAGE_RW)
#define __PAGE_KERNEL_RX		(__PAGE_KERNEL_EXEC & ~_PAGE_RW)
#define __PAGE_KERNEL_NOCACHE		(__PAGE_KERNEL | _PAGE_NOCACHE)
#define __PAGE_KERNEL_VSYSCALL		(__PAGE_KERNEL_RX | _PAGE_USER)
#define __PAGE_KERNEL_VVAR		(__PAGE_KERNEL_RO | _PAGE_USER)
#define __PAGE_KERNEL_LARGE		(__PAGE_KERNEL | _PAGE_PSE)
#define __PAGE_KERNEL_LARGE_EXEC	(__PAGE_KERNEL_EXEC | _PAGE_PSE)

#define __PAGE_KERNEL_IO		(__PAGE_KERNEL)
#define __PAGE_KERNEL_IO_NOCACHE	(__PAGE_KERNEL_NOCACHE)

#define PAGE_KERNEL			__pgprot(__PAGE_KERNEL)
#define PAGE_KERNEL_RO			__pgprot(__PAGE_KERNEL_RO)
#define PAGE_KERNEL_EXEC		__pgprot(__PAGE_KERNEL_EXEC)
#define PAGE_KERNEL_RX			__pgprot(__PAGE_KERNEL_RX)
#define PAGE_KERNEL_NOCACHE		__pgprot(__PAGE_KERNEL_NOCACHE)
#define PAGE_KERNEL_LARGE		__pgprot(__PAGE_KERNEL_LARGE)
#define PAGE_KERNEL_LARGE_EXEC		__pgprot(__PAGE_KERNEL_LARGE_EXEC)
#define PAGE_KERNEL_VSYSCALL		__pgprot(__PAGE_KERNEL_VSYSCALL)
#define PAGE_KERNEL_VVAR		__pgprot(__PAGE_KERNEL_VVAR)

#define PAGE_KERNEL_IO			__pgprot(__PAGE_KERNEL_IO)
#define PAGE_KERNEL_IO_NOCACHE		__pgprot(__PAGE_KERNEL_IO_NOCACHE)

/*         xwr */
#define __P000	PAGE_NONE
#define __P001	PAGE_READONLY
#define __P010	PAGE_COPY
#define __P011	PAGE_COPY
#define __P100	PAGE_READONLY_EXEC
#define __P101	PAGE_READONLY_EXEC
#define __P110	PAGE_COPY_EXEC
#define __P111	PAGE_COPY_EXEC

#define __S000	PAGE_NONE
#define __S001	PAGE_READONLY
#define __S010	PAGE_SHARED
#define __S011	PAGE_SHARED
#define __S100	PAGE_READONLY_EXEC
#define __S101	PAGE_READONLY_EXEC
#define __S110	PAGE_SHARED_EXEC
#define __S111	PAGE_SHARED_EXEC

/*
 * early identity mapping  pte attrib macros.
 */
#ifdef CONFIG_X86_64
#define __PAGE_KERNEL_IDENT_LARGE_EXEC	__PAGE_KERNEL_LARGE_EXEC
#endif

/*
 * PGDIR_SHIFT determines what a top-level page table entry can map
 */
#define PGDIR_SHIFT	39
#define PTRS_PER_PGD	512

/*
 * 3rd level page
 */
#define PUD_SHIFT	30
#define PTRS_PER_PUD	512

/*
 * PMD_SHIFT determines the size of the area a middle-level
 * page table can map
 */
#define PMD_SHIFT	21
#define PTRS_PER_PMD	512

/*
 * entries per page directory level
 */
#define PTRS_PER_PTE	512

#define PMD_SIZE	(_AC(1, UL) << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE - 1))
#define PUD_SIZE	(_AC(1, UL) << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE - 1))
#define PGDIR_SIZE	(_AC(1, UL) << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE - 1))

#define MAX_PHYSMEM_BITS	46

#define MAXMEM			_AC(__AC(1, UL) << MAX_PHYSMEM_BITS, UL)
#define VMALLOC_SIZE_TB		_AC(32, UL)
#define VMALLOC_BASE		_AC(0xffffc90000000000, UL)
#define VMEMMAP_BASE		_AC(0xffffea0000000000, UL)
#define VMALLOC_END		(VMALLOC_START + _AC((VMALLOC_SIZE_TB << 40) - 1, UL))
#define MODULES_VADDR   	 (__START_KERNEL_map + KERNEL_IMAGE_SIZE)
#define MODULES_END		_AC(0xffffffffff000000, UL)
#define MODULES_LEN		(MODULES_END - MODULES_VADDR)
#define ESPFIX_PGD_ENTRY	_AC(-2, UL)
#define ESPFIX_BASE_ADDR	(ESPFIX_PGD_ENTRY << PGDIR_SHIFT)
#define EFI_VA_START		( -4 * (_AC(1, UL) << 30))
#define EFI_VA_END		(-68 * (_AC(1, UL) << 30))

#define EARLY_DYNAMIC_PAGE_TABLES	64

/*
 * Kernel image size is limited to 1GiB due to the fixmap living in the
 * next 1GiB (see level2_kernel_pgt in arch/x86/kernel/head_64.S). Use
 * 512MiB by default, leaving 1.5GiB for modules once the page tables
 * are fully set up.
 */
#define KERNEL_IMAGE_SIZE	(512 * 1024 * 1024)

/* Extracts the PFN from a (pte|pmd|pud|pgd)val_t of a 4KB page */
#define PTE_PFN_MASK		((pteval_t)PHYSICAL_PAGE_MASK)
#define PTE_VFN_MASK		((pteval_t)VIRTUAL_PAGE_MASK)

/*
 *  Extracts the flags from a (pte|pmd|pud|pgd)val_t
 *  This includes the protection key value.
 */
#define PTE_FLAGS_MASK		(~PTE_PFN_MASK)

#ifndef __ASSEMBLY__

/* These are used to make use of C type-checking. */
typedef unsigned long	pteval_t;
typedef unsigned long	pmdval_t;
typedef unsigned long	pudval_t;
typedef unsigned long	pgdval_t;
typedef unsigned long	pgprotval_t;

typedef struct { pteval_t pte; } pte_t;
typedef struct { pmdval_t pmd; } pmd_t;
typedef struct { pudval_t pud; } pud_t;
typedef struct { pgdval_t pgd; } pgd_t;
typedef struct { pgprotval_t pgprot; } pgprot_t;

/*
 * PGD level 4
 */

static inline pgd_t native_make_pgd(pgdval_t val)
{
	return (pgd_t) { val };
}

static inline pgdval_t native_pgd_val(pgd_t pgd)
{
	return pgd.pgd;
}

static inline pgdval_t pgd_flags(pgd_t pgd)
{
	return native_pgd_val(pgd) & PTE_FLAGS_MASK;
}

/*
 * PUD level 3
 */

static inline pud_t native_make_pud(pmdval_t val)
{
	return (pud_t) { val };
}

static inline pudval_t native_pud_val(pud_t pud)
{
	return pud.pud;
}

/*
 * PMD level 2
 */

static inline pmd_t native_make_pmd(pmdval_t val)
{
	return (pmd_t) { val };
}

static inline pmdval_t native_pmd_val(pmd_t pmd)
{
	return pmd.pmd;
}

static inline pudval_t pud_pfn_mask(pud_t pud)
{
	if (native_pud_val(pud) & _PAGE_PSE)
		return PHYSICAL_PUD_PAGE_MASK;
	else
		return PTE_PFN_MASK;
}

static inline pudval_t pud_flags_mask(pud_t pud)
{
	return ~pud_pfn_mask(pud);
}

static inline pudval_t pud_flags(pud_t pud)
{
	return native_pud_val(pud) & pud_flags_mask(pud);
}

static inline pmdval_t pmd_pfn_mask(pmd_t pmd)
{
	if (native_pmd_val(pmd) & _PAGE_PSE)
		return PHYSICAL_PMD_PAGE_MASK;
	else
		return PTE_PFN_MASK;
}

static inline pmdval_t pmd_flags_mask(pmd_t pmd)
{
	return ~pmd_pfn_mask(pmd);
}

static inline pmdval_t pmd_flags(pmd_t pmd)
{
	return native_pmd_val(pmd) & pmd_flags_mask(pmd);
}

static inline pte_t native_make_pte(pteval_t val)
{
	return (pte_t) { .pte = val };
}

static inline pteval_t native_pte_val(pte_t pte)
{
	return pte.pte;
}

static inline pteval_t pte_flags(pte_t pte)
{
	return native_pte_val(pte) & PTE_FLAGS_MASK;
}

#define pgd_val(x)	native_pgd_val(x)
#define __pgd(x)	native_make_pgd(x)

#define pud_val(x)	native_pud_val(x)
#define __pud(x)	native_make_pud(x)

#define pmd_val(x)	native_pmd_val(x)
#define __pmd(x)	native_make_pmd(x)

#define pte_val(x)	native_pte_val(x)
#define __pte(x)	native_make_pte(x)

#define pgprot_val(x)	((x).pgprot)
#define __pgprot(x)	((pgprot_t) { (x) } )

enum pg_level {
	PG_LEVEL_NONE,
	PG_LEVEL_4K,
	PG_LEVEL_2M,
	PG_LEVEL_1G,
	PG_LEVEL_NUM
};

extern pteval_t __supported_pte_mask;

/*
 * Mask out unsupported bits in a present pgprot.  Non-present pgprots
 * can use those bits for other purposes, so leave them be.
 */
static inline pgprotval_t massage_pgprot(pgprot_t pgprot)
{
	pgprotval_t protval = pgprot_val(pgprot);

	if (protval & _PAGE_PRESENT)
		protval &= __supported_pte_mask;

	return protval;
}

/*
 * The cache modes defined here are used to translate between pure SW usage
 * and the HW defined cache mode bits and/or PAT entries.
 *
 * The resulting bits for PWT, PCD and PAT should be chosen in a way
 * to have the WB mode at index 0 (all bits clear). This is the default
 * right now and likely would break too much if changed.
 */
enum page_cache_mode {
	_PAGE_CACHE_MODE_WB = 0,
	_PAGE_CACHE_MODE_WC = 1,
	_PAGE_CACHE_MODE_UC_MINUS = 2,
	_PAGE_CACHE_MODE_UC = 3,
	_PAGE_CACHE_MODE_WT = 4,
	_PAGE_CACHE_MODE_WP = 5,
	_PAGE_CACHE_MODE_NUM = 8
};

#define _PAGE_CACHE_MASK	(_PAGE_PAT | _PAGE_PCD | _PAGE_PWT)
#define _PAGE_NOCACHE		(cachemode2protval(_PAGE_CACHE_MODE_UC))

extern u16 __cachemode2pte_tbl[_PAGE_CACHE_MODE_NUM];
extern u8 __pte2cachemode_tbl[8];

#define __pte2cm_idx(cb)				\
	((((cb) >> (_PAGE_BIT_PAT - 2)) & 4) |		\
	 (((cb) >> (_PAGE_BIT_PCD - 1)) & 2) |		\
	 (((cb) >> _PAGE_BIT_PWT) & 1))

#define __cm_idx2pte(i)					\
	((((i) & 4) << (_PAGE_BIT_PAT - 2)) |		\
	 (((i) & 2) << (_PAGE_BIT_PCD - 1)) |		\
	 (((i) & 1) << _PAGE_BIT_PWT))

static inline unsigned long cachemode2protval(enum page_cache_mode pcm)
{
	if (likely(pcm == 0))
		return 0;
	return __cachemode2pte_tbl[pcm];
}

static inline pgprot_t cachemode2pgprot(enum page_cache_mode pcm)
{
	return __pgprot(cachemode2protval(pcm));
}

static inline enum page_cache_mode pgprot2cachemode(pgprot_t pgprot)
{
	unsigned long masked;

	masked = pgprot_val(pgprot) & _PAGE_CACHE_MASK;
	if (likely(masked == 0))
		return 0;
	return __pte2cachemode_tbl[__pte2cm_idx(masked)];
}

static inline pgprot_t pgprot_4k_2_large(pgprot_t pgprot)
{
	pgprotval_t val = pgprot_val(pgprot);
	pgprot_t new;

	pgprot_val(new) = (val & ~(_PAGE_PAT | _PAGE_PAT_LARGE)) |
		((val & _PAGE_PAT) << (_PAGE_BIT_PAT_LARGE - _PAGE_BIT_PAT));
	return new;
}

static inline pgprot_t pgprot_large_2_4k(pgprot_t pgprot)
{
	pgprotval_t val = pgprot_val(pgprot);
	pgprot_t new;

	pgprot_val(new) = (val & ~(_PAGE_PAT | _PAGE_PAT_LARGE)) |
			  ((val & _PAGE_PAT_LARGE) >>
			   (_PAGE_BIT_PAT_LARGE - _PAGE_BIT_PAT));
	return new;
}

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_PGTABLE_TYPES_H_ */
