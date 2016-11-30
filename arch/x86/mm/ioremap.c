/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/asm.h>
#include <asm/page.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include <lego/kernel.h>
#include <lego/string.h>
#include <lego/early_ioremap.h>

/*
 * For early_ioremap/unmap
 * we have 512 temporaty boot-time mappings, which will use
 * just one PMD entry, this is different from the level1_fixmap_pgt.
 */
static pte_t bm_pte[PAGE_SIZE/sizeof(pte_t)] __page_aligned_bss;

static inline pmd_t * __init early_ioremap_pmd(unsigned long addr)
{
	/* Don't assume we're using swapper_pg_dir at this point */
	pgd_t *base = __va(read_cr3());
	pgd_t *pgd = &base[pgd_index(addr)];
	pud_t *pud = pud_offset(pgd, addr);
	pmd_t *pmd = pmd_offset(pud, addr);

	return pmd;
}

static inline pte_t * __init early_ioremap_pte(unsigned long addr)
{
	return &bm_pte[pte_index(addr)];
}

bool __init is_early_ioremap_ptep(pte_t *ptep)
{
	return ptep >= &bm_pte[0] && ptep < &bm_pte[PAGE_SIZE/sizeof(pte_t)];
}

void __init __early_ioremap_set_fixmap(enum fixed_addresses idx,
				       phys_addr_t phys,
				       pgprot_t flags)
{
	unsigned long addr = __fix_to_virt(idx);
	pte_t *ptep;

	if (idx <= __end_of_permanent_fixed_addresses) {
		panic("Use __set_fixmap for permanent fixmap");
		return;
	}

	if (idx >= __end_of_fixed_addresses) {
		BUG();
		return;
	}

	ptep = early_ioremap_pte(addr);

	if (early_ioremap_debug)
		pr_debug("__early_ioremap_set_fixmap(%pS): %#lx -> %#llx\n",
			ptep, addr, phys & PTE_PFN_MASK);

	if (pgprot_val(flags))
		pte_set(ptep, pfn_pte(phys >> PAGE_SHIFT, flags));
	else
		pte_clear(ptep);

	__flush_tlb_one(addr);
}

static void __init __set_fixmap_pte(unsigned long addr, pte_t pte)
{
	/*
	 * Don't assume we're using swapper_pg_dir at this point
	 * And we are guaranteed that all levels of page table will
	 * exist (because of head_64.S and some BUILD_BUG_ON check below)
	 */
	pgd_t *base = __va(read_cr3());
	pgd_t *pgd = &base[pgd_index(addr)];
	pud_t *pud = pud_offset(pgd, addr);
	pmd_t *pmd = pmd_offset(pud, addr);
	pte_t *ptep = pte_offset_kernel(pmd, addr);

	if (early_ioremap_debug)
		pr_debug("__set_fixmap_pte(%pS): %#lx -> %#lx\n",
			ptep, addr, pte_val(pte) & PTE_PFN_MASK);

	pte_set(ptep, pte);

	__flush_tlb_one(addr);
}

/*
 * Used by permanent fixmap only
 */
void __init __set_fixmap(enum fixed_addresses idx, phys_addr_t phys,
		         pgprot_t flags)
{
	unsigned long address = __fix_to_virt(idx);
	pte_t pte = pfn_pte(phys >> PAGE_SHIFT, flags);

	if (idx >= __end_of_permanent_fixed_addresses) {
		BUG();
		return;
	}
	__set_fixmap_pte(address, pte);
}

/*
 * Arch-specific early ioremap initialization
 * Afterwards, early_ioremap/iounmap and fixmap are ready to use.
 */
void __init early_ioremap_init(void)
{
	pmd_t *pmd;

	/*
	 * In head_64.S, we only have one level1_fixmap_pgt
	 * installed at PMD (level2_fixmap_pgt). So the size
	 * of permanent fixed address is limited to PMD_SIZE:
	 */
	BUILD_BUG_ON(__fix_to_virt(__end_of_permanent_fixed_addresses)
		< (~0UL - PMD_SIZE));

	/*
	 * If head_64.S, the level3_kernel_pgt's entry 511 is
	 * used for map kernel code+data+bss, and the entry 512
	 * is used for fixmap.
	 *
	 * Hence the minimum address of fixmap can NOT be lower
	 * than the range mapped by entry 512, which is the size
	 * that a PUD can map (PUD_SIZE):
	 */
	BUILD_BUG_ON(__fix_to_virt(__end_of_fixed_addresses)
			< (~0UL - PUD_SIZE));

	/* Must be PMD aligned */
	BUILD_BUG_ON((fix_to_virt(0) + PAGE_SIZE) & ((1 << PMD_SHIFT) - 1));

	/*
	 * The boot-ioremap range spans multiple pmds, for which
	 * we are not prepared:
	 */
	BUILD_BUG_ON((__fix_to_virt(FIX_BTMAP_BEGIN) >> PMD_SHIFT)
		     != (__fix_to_virt(FIX_BTMAP_END) >> PMD_SHIFT));

	/*
	 * Only involve permarnent fixmap addresses.
	 * Those boot-time slots are not calculated here.
	 */
	pr_info("fixmap: [%#lx - %#lx]\n", FIXADDR_START, FIXADDR_TOP);
	pr_info("early_ioremap: [%#lx - %#lx]\n",
		fix_to_virt(FIX_BTMAP_BEGIN), fix_to_virt(FIX_BTMAP_END));

	/* Generic early ioremap setup */
	early_ioremap_setup();

	pmd = early_ioremap_pmd(fix_to_virt(FIX_BTMAP_BEGIN));
	memset(bm_pte, 0, sizeof(bm_pte));
	pmd_set(pmd, __pmd(__pa(bm_pte) | _PAGE_TABLE));

	if (pmd != early_ioremap_pmd(fix_to_virt(FIX_BTMAP_END))) {
		WARN_ON(1);
		printk(KERN_WARNING "pmd %p != %p\n",
		       pmd, early_ioremap_pmd(fix_to_virt(FIX_BTMAP_END)));
		printk(KERN_WARNING "fix_to_virt(FIX_BTMAP_BEGIN): %08lx\n",
			fix_to_virt(FIX_BTMAP_BEGIN));
		printk(KERN_WARNING "fix_to_virt(FIX_BTMAP_END):   %08lx\n",
			fix_to_virt(FIX_BTMAP_END));

		printk(KERN_WARNING "FIX_BTMAP_END:       %d\n", FIX_BTMAP_END);
		printk(KERN_WARNING "FIX_BTMAP_BEGIN:     %d\n",
		       FIX_BTMAP_BEGIN);
	}
}
