/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/io.h>
#include <asm/asm.h>
#include <asm/e820.h>
#include <asm/page.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include <lego/mm.h>
#include <lego/kernel.h>
#include <lego/string.h>
#include <lego/vmalloc.h>
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
		pr_debug("  __early_ioremap_set_fixmap(%pS): %#lx -> %#llx\n",
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
		pr_debug("  __set_fixmap_pte(%pS): %#lx -> %#lx\n",
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

#if 0
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
#endif

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

static int __ioremap_check_ram(unsigned long start_pfn, unsigned long nr_pages,
			       void *arg)
{
	unsigned long i;

	for (i = 0; i < nr_pages; ++i)
		if (pfn_valid(start_pfn + i) &&
		    !PageReserved(pfn_to_page(start_pfn + i)))
			return 1;
	return 0;
}

/**
 * iounmap - Free a IO remapping
 * @addr: virtual address from ioremap_*
 *
 * Caller must ensure there is only one unmapping for the same pointer.
 */
void iounmap(volatile void __iomem *addr)
{
}

static int ioremap_pte_range(pmd_t *pmd, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pte_t *pte;
	u64 pfn;

	pfn = phys_addr >> PAGE_SHIFT;
	pte = pte_alloc_kernel(pmd, addr);
	if (!pte)
		return -ENOMEM;
	do {
		BUG_ON(!pte_none(*pte));
		pte_set(pte, pfn_pte(pfn, prot));
		pfn++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
	return 0;
}

static inline int ioremap_pmd_range(pud_t *pud, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;

	phys_addr -= addr;
	pmd = pmd_alloc(&init_mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);
		if (ioremap_pte_range(pmd, addr, next, phys_addr + addr, prot))
			return -ENOMEM;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

static inline int ioremap_pud_range(pgd_t *pgd, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pud_t *pud;
	unsigned long next;

	phys_addr -= addr;
	pud = pud_alloc(&init_mm, pgd, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		if (ioremap_pmd_range(pud, addr, next, phys_addr + addr, prot))
			return -ENOMEM;
	} while (pud++, addr = next, addr != end);
	return 0;
}

static int ioremap_page_range(unsigned long addr, unsigned long end,
			      phys_addr_t phys_addr, pgprot_t prot)
{
	pgd_t *pgd;
	unsigned long start;
	unsigned long next;
	int err;

	BUG_ON(addr >= end);

	start = addr;
	phys_addr -= addr;
	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		err = ioremap_pud_range(pgd, addr, next, phys_addr+addr, prot);
		if (err)
			break;
	} while (pgd++, addr = next, addr != end);

	return err;
}

/*
 * Remap an arbitrary physical address space into the kernel virtual
 * address space. It transparently creates kernel huge I/O mapping when
 * the physical address is aligned by a huge page size (1GB or 2MB) and
 * the requested size is at least the huge page size.
 *
 * NOTE: MTRRs can override PAT memory types with a 4KB granularity.
 * Therefore, the mapping code falls back to use a smaller page toward 4KB
 * when a mapping range is covered by non-WB type of MTRRs.
 *
 * NOTE! We need to allow non-page-aligned mappings too: we will obviously
 * have to convert them into an offset in a page-aligned mapping, but the
 * caller shouldn't need to know that small detail.
 */
static void __iomem *__ioremap_caller(resource_size_t phys_addr,
		unsigned long size, enum page_cache_mode pcm, void *caller)
{
	unsigned long offset, vaddr;
	void __iomem *ret_addr;
	unsigned long last_addr;
	unsigned long pfn, last_pfn;
	struct vm_struct *area;
	pgprot_t prot;

	/* Don't allow wraparound or zero size */
	last_addr = phys_addr + size - 1;
	if (!size || last_addr < phys_addr)
		return NULL;

	if (!phys_addr_valid(phys_addr)) {
		pr_warn("ioremap: invalid physical address %llx\n",
		       (unsigned long long)phys_addr);
		WARN_ON(1);
		return NULL;
	}

	/*
	 * Don't remap the low PCI/ISA area,
	 * it's always mapped..
	 */
	if (is_ISA_range(phys_addr, last_addr))
		return (void __iomem *)phys_to_virt(phys_addr);

	/* Don't allow anybody to remap normal RAM that we're using */
	pfn      = phys_addr >> PAGE_SHIFT;
	last_pfn = last_addr >> PAGE_SHIFT;
	if (walk_system_ram_range(pfn, last_pfn - pfn + 1, NULL,
			  __ioremap_check_ram) == 1) {
		WARN(1, "ioremap on RAM at %pa - %pa\n", &phys_addr, &last_addr);
		return NULL;
	}

	/* Mappings have to be page-aligneg: */
	offset = phys_addr & ~PAGE_MASK;
	phys_addr &= PHYSICAL_PAGE_MASK;
	size = PAGE_ALIGN(last_addr+1) - phys_addr;

	prot = PAGE_KERNEL_IO;
	switch (pcm) {
	case _PAGE_CACHE_MODE_UC:
	default:
		prot = __pgprot(pgprot_val(prot) |
				cachemode2protval(_PAGE_CACHE_MODE_UC));
		break;
	case _PAGE_CACHE_MODE_UC_MINUS:
		prot = __pgprot(pgprot_val(prot) |
				cachemode2protval(_PAGE_CACHE_MODE_UC_MINUS));
		break;
	case _PAGE_CACHE_MODE_WC:
		prot = __pgprot(pgprot_val(prot) |
				cachemode2protval(_PAGE_CACHE_MODE_WC));
		break;
	case _PAGE_CACHE_MODE_WT:
		prot = __pgprot(pgprot_val(prot) |
				cachemode2protval(_PAGE_CACHE_MODE_WT));
		break;
	case _PAGE_CACHE_MODE_WB:
		break;
	}

	/* Get available kernel virtual address slot */
	area = get_vm_area_caller(size, VM_IOREMAP, caller);
	if (!area)
		return NULL;

	area->phys_addr = phys_addr;
	vaddr = (unsigned long)area->addr;

	/* Do the real pgtable mapping */
	if (ioremap_page_range(vaddr, vaddr + size, phys_addr, prot))
		goto err_free_area;

	ret_addr = (void __iomem *) (vaddr + offset);
	return ret_addr;

err_free_area:
	free_vm_area(area);
	return NULL;
}

/**
 * ioremap_nocache     -   map bus memory into CPU space
 * @phys_addr:    bus address of the memory
 * @size:      size of the resource to map
 *
 * ioremap_nocache performs a platform specific sequence of operations to
 * make bus memory CPU accessible via the readb/readw/readl/writeb/
 * writew/writel functions and the other mmio helpers. The returned
 * address is not guaranteed to be usable directly as a virtual
 * address.
 *
 * This version of ioremap ensures that the memory is marked uncachable
 * on the CPU as well as honouring existing caching rules from things like
 * the PCI bus. Note that there are other caches and buffers on many
 * busses. In particular driver authors should read up on PCI writes
 *
 * It's useful if some control registers are in such an area and
 * write combining or read caching is not desirable:
 *
 * Must be freed with iounmap.
 */
void __iomem *ioremap_nocache(resource_size_t phys_addr, unsigned long size)
{
	/*
	 * Ideally, this should be:
	 *	pat_enabled() ? _PAGE_CACHE_MODE_UC : _PAGE_CACHE_MODE_UC_MINUS;
	 *
	 * Till we fix all X drivers to use ioremap_wc(), we will use
	 * UC MINUS. Drivers that are certain they need or can already
	 * be converted over to strong UC can use ioremap_uc().
	 */
	enum page_cache_mode pcm = _PAGE_CACHE_MODE_UC_MINUS;

	return __ioremap_caller(phys_addr, size, pcm,
				__builtin_return_address(0));
}

/**
 * ioremap_uc     -   map bus memory into CPU space as strongly uncachable
 * @phys_addr:    bus address of the memory
 * @size:      size of the resource to map
 *
 * ioremap_uc performs a platform specific sequence of operations to
 * make bus memory CPU accessible via the readb/readw/readl/writeb/
 * writew/writel functions and the other mmio helpers. The returned
 * address is not guaranteed to be usable directly as a virtual
 * address.
 *
 * This version of ioremap ensures that the memory is marked with a strong
 * preference as completely uncachable on the CPU when possible. For non-PAT
 * systems this ends up setting page-attribute flags PCD=1, PWT=1. For PAT
 * systems this will set the PAT entry for the pages as strong UC.  This call
 * will honor existing caching rules from things like the PCI bus. Note that
 * there are other caches and buffers on many busses. In particular driver
 * authors should read up on PCI writes.
 *
 * It's useful if some control registers are in such an area and
 * write combining or read caching is not desirable:
 *
 * Must be freed with iounmap.
 */
void __iomem *ioremap_uc(resource_size_t phys_addr, unsigned long size)
{
	enum page_cache_mode pcm = _PAGE_CACHE_MODE_UC;

	return __ioremap_caller(phys_addr, size, pcm,
				__builtin_return_address(0));
}

/**
 * ioremap_wc	-	map memory into CPU space write combined
 * @phys_addr:	bus address of the memory
 * @size:	size of the resource to map
 *
 * This version of ioremap ensures that the memory is marked write combining.
 * Write combining allows faster writes to some hardware devices.
 *
 * Must be freed with iounmap.
 */
void __iomem *ioremap_wc(resource_size_t phys_addr, unsigned long size)
{
	return __ioremap_caller(phys_addr, size, _PAGE_CACHE_MODE_WC,
					__builtin_return_address(0));
}

/**
 * ioremap_wt	-	map memory into CPU space write through
 * @phys_addr:	bus address of the memory
 * @size:	size of the resource to map
 *
 * This version of ioremap ensures that the memory is marked write through.
 * Write through stores data into memory while keeping the cache up-to-date.
 *
 * Must be freed with iounmap.
 */
void __iomem *ioremap_wt(resource_size_t phys_addr, unsigned long size)
{
	return __ioremap_caller(phys_addr, size, _PAGE_CACHE_MODE_WT,
					__builtin_return_address(0));
}

void __iomem *ioremap_cache(resource_size_t phys_addr, unsigned long size)
{
	return __ioremap_caller(phys_addr, size, _PAGE_CACHE_MODE_WB,
				__builtin_return_address(0));
}

void __iomem *ioremap_prot(resource_size_t phys_addr, unsigned long size,
				unsigned long prot_val)
{
	return __ioremap_caller(phys_addr, size,
				pgprot2cachemode(__pgprot(prot_val)),
				__builtin_return_address(0));
}
