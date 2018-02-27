/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/asm.h>
#include <asm/dma.h>
#include <asm/e820.h>
#include <asm/page.h>
#include <asm/setup.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/processor.h>

#include <lego/mm.h>
#include <lego/numa.h>
#include <lego/list.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/memblock.h>
#include <lego/seq_file.h>

/*
 * Tables translating between page_cache_type_t and pte encoding.
 *
 * The default values are defined statically as minimal supported mode;
 * WC and WT fall back to UC-.  pat_init() updates these values to support
 * more cache modes, WC and WT, when it is safe to do so.  See pat_init()
 * for the details.  Note, __early_ioremap() used during early boot-time
 * takes pgprot_t (pte encoding) and does not use these tables.
 *
 *   Index into __cachemode2pte_tbl[] is the cachemode.
 *
 *   Index into __pte2cachemode_tbl[] are the caching attribute bits of the pte
 *   (_PAGE_PWT, _PAGE_PCD, _PAGE_PAT) at index bit positions 0, 1, 2.
 */
u16 __cachemode2pte_tbl[_PAGE_CACHE_MODE_NUM] = {
	[_PAGE_CACHE_MODE_WB      ]	= 0         | 0        ,
	[_PAGE_CACHE_MODE_WC      ]	= 0         | _PAGE_PCD,
	[_PAGE_CACHE_MODE_UC_MINUS]	= 0         | _PAGE_PCD,
	[_PAGE_CACHE_MODE_UC      ]	= _PAGE_PWT | _PAGE_PCD,
	[_PAGE_CACHE_MODE_WT      ]	= 0         | _PAGE_PCD,
	[_PAGE_CACHE_MODE_WP      ]	= 0         | _PAGE_PCD,
};

u8 __pte2cachemode_tbl[8] = {
	[__pte2cm_idx( 0        | 0         | 0        )] = _PAGE_CACHE_MODE_WB,
	[__pte2cm_idx(_PAGE_PWT | 0         | 0        )] = _PAGE_CACHE_MODE_UC_MINUS,
	[__pte2cm_idx( 0        | _PAGE_PCD | 0        )] = _PAGE_CACHE_MODE_UC_MINUS,
	[__pte2cm_idx(_PAGE_PWT | _PAGE_PCD | 0        )] = _PAGE_CACHE_MODE_UC,
	[__pte2cm_idx( 0        | 0         | _PAGE_PAT)] = _PAGE_CACHE_MODE_WB,
	[__pte2cm_idx(_PAGE_PWT | 0         | _PAGE_PAT)] = _PAGE_CACHE_MODE_UC_MINUS,
	[__pte2cm_idx(0         | _PAGE_PCD | _PAGE_PAT)] = _PAGE_CACHE_MODE_UC_MINUS,
	[__pte2cm_idx(_PAGE_PWT | _PAGE_PCD | _PAGE_PAT)] = _PAGE_CACHE_MODE_UC,
};

pteval_t __supported_pte_mask __read_mostly = ~0;

static unsigned long __initdata pgt_buf_start;
static unsigned long __initdata pgt_buf_end;
static unsigned long __initdata pgt_buf_top;
static bool __initdata can_use_brk_pgt = true;

static unsigned long min_pfn_mapped;

/*
 * Pages returned are already directly mapped.
 */
static void *alloc_low_pages(unsigned int num)
{
	unsigned long pfn;
	int i;

	if ((pgt_buf_end + num) > pgt_buf_top || !can_use_brk_pgt) {
		unsigned long ret;
		if (min_pfn_mapped >= max_pfn_mapped)
			panic("alloc_low_pages: ran out of memory");
		ret = memblock_find_in_range(min_pfn_mapped << PAGE_SHIFT,
					max_pfn_mapped << PAGE_SHIFT,
					PAGE_SIZE * num , PAGE_SIZE);
		if (!ret)
			panic("alloc_low_pages: can not alloc memory");
		memblock_reserve(ret, PAGE_SIZE * num);
		pfn = ret >> PAGE_SHIFT;
	} else {
		pfn = pgt_buf_end;
		pgt_buf_end += num;
		printk(KERN_DEBUG "BRK [%#010lx, %#010lx] PGTABLE\n",
			pfn << PAGE_SHIFT, (pgt_buf_end << PAGE_SHIFT) - 1);
	}

	for (i = 0; i < num; i++) {
		void *adr;

		adr = __va((pfn + i) << PAGE_SHIFT);
		clear_page(adr);
	}

	return __va(pfn << PAGE_SHIFT);
}

static inline void *alloc_low_page(void)
{
	return alloc_low_pages(1);
}

/*
 * By default
 *  3 4k for initial PMD_SIZE,
 *  3 4k for 0-ISA_END_ADDRESS.
 */
#define INIT_PGD_PAGE_COUNT      6
#define INIT_PGT_BUF_SIZE	(INIT_PGD_PAGE_COUNT * PAGE_SIZE)

RESERVE_BRK(early_pgt_alloc, INIT_PGT_BUF_SIZE);

void  __init early_alloc_pgt_buf(void)
{
	unsigned long tables = INIT_PGT_BUF_SIZE;
	phys_addr_t base;

	base = __pa(extend_brk(tables, PAGE_SIZE));

	pgt_buf_start = base >> PAGE_SHIFT;
	pgt_buf_end = pgt_buf_start;
	pgt_buf_top = pgt_buf_start + (tables >> PAGE_SHIFT);
}

struct map_range {
	unsigned long start;
	unsigned long end;
	unsigned page_size_mask;
};

#ifdef CONFIG_X86_32
# define NR_RANGE_MR 3
#else
# define NR_RANGE_MR 5
#endif

int direct_gbpages = IS_ENABLED(CONFIG_X86_DIRECT_GBPAGES);
static int page_size_mask;

static void __init probe_page_size_mask(void)
{
	/* Enable PSE if available */
	if (cpu_has(X86_FEATURE_PSE)) {
		page_size_mask |= 1 << PG_LEVEL_2M;
		cr4_set_bits_and_update_boot(X86_CR4_PSE);
	}

	/* Enable PGE if available */
	if (cpu_has(X86_FEATURE_PGE)) {
		cr4_set_bits_and_update_boot(X86_CR4_PGE);
		__supported_pte_mask |= _PAGE_GLOBAL;
	} else
		__supported_pte_mask &= ~_PAGE_GLOBAL;

	/* Enable 1 GB linear kernel mappings if available: */
	if (direct_gbpages && cpu_has(X86_FEATURE_GBPAGES)) {
		pr_info("Using GB pages for direct mapping\n");
		page_size_mask |= 1 << PG_LEVEL_1G;
	} else {
		direct_gbpages = 0;
	}
}

static const char *page_size_string(struct map_range *mr)
{
	static const char str_1g[] = "1G";
	static const char str_2m[] = "2M";
	static const char str_4k[] = "4k";

	if (mr->page_size_mask & (1<<PG_LEVEL_1G))
		return str_1g;

	if (mr->page_size_mask & (1<<PG_LEVEL_2M))
		return str_2m;

	return str_4k;
}

/*
 * adjust the page_size_mask for small range to go with
 *	big page size instead small one if nearby are ram too.
 */
static void adjust_range_page_size_mask(struct map_range *mr, int nr_range)
{
	int i;

	for (i = 0; i < nr_range; i++) {
		if ((page_size_mask & (1<<PG_LEVEL_2M)) &&
		    !(mr[i].page_size_mask & (1<<PG_LEVEL_2M))) {
			unsigned long start = round_down(mr[i].start, PMD_SIZE);
			unsigned long end = round_up(mr[i].end, PMD_SIZE);

#ifdef CONFIG_X86_32
			if ((end >> PAGE_SHIFT) > max_low_pfn)
				continue;
#endif

			if (memblock_is_region_memory(start, end - start))
				mr[i].page_size_mask |= 1<<PG_LEVEL_2M;
		}
		if ((page_size_mask & (1<<PG_LEVEL_1G)) &&
		    !(mr[i].page_size_mask & (1<<PG_LEVEL_1G))) {
			unsigned long start = round_down(mr[i].start, PUD_SIZE);
			unsigned long end = round_up(mr[i].end, PUD_SIZE);

			if (memblock_is_region_memory(start, end - start))
				mr[i].page_size_mask |= 1<<PG_LEVEL_1G;
		}
	}
}

static int save_mr(struct map_range *mr, int nr_range,
		   unsigned long start_pfn, unsigned long end_pfn,
		   unsigned long page_size_mask)
{
	if (start_pfn < end_pfn) {
		if (nr_range >= NR_RANGE_MR)
			panic("run out of nr_range\n");
		mr[nr_range].start = start_pfn<<PAGE_SHIFT;
		mr[nr_range].end   = end_pfn<<PAGE_SHIFT;
		mr[nr_range].page_size_mask = page_size_mask;
		nr_range++;
	}

	return nr_range;
}

static int split_mem_range(struct map_range *mr, int nr_range,
			   unsigned long start, unsigned long end)
{
	unsigned long start_pfn, end_pfn, limit_pfn;
	unsigned long pfn;
	int i;

	limit_pfn = PFN_DOWN(end);

	/* head if not big page alignment ? */
	pfn = start_pfn = PFN_DOWN(start);
#ifdef CONFIG_X86_32
	/*
	 * Don't use a large page for the first 2/4MB of memory
	 * because there are often fixed size MTRRs in there
	 * and overlapping MTRRs into large pages can cause
	 * slowdowns.
	 */
	if (pfn == 0)
		end_pfn = PFN_DOWN(PMD_SIZE);
	else
		end_pfn = round_up(pfn, PFN_DOWN(PMD_SIZE));
#else /* CONFIG_X86_64 */
	end_pfn = round_up(pfn, PFN_DOWN(PMD_SIZE));
#endif
	if (end_pfn > limit_pfn)
		end_pfn = limit_pfn;
	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn, 0);
		pfn = end_pfn;
	}

	/* big page (2M) range */
	start_pfn = round_up(pfn, PFN_DOWN(PMD_SIZE));
#ifdef CONFIG_X86_32
	end_pfn = round_down(limit_pfn, PFN_DOWN(PMD_SIZE));
#else /* CONFIG_X86_64 */
	end_pfn = round_up(pfn, PFN_DOWN(PUD_SIZE));
	if (end_pfn > round_down(limit_pfn, PFN_DOWN(PMD_SIZE)))
		end_pfn = round_down(limit_pfn, PFN_DOWN(PMD_SIZE));
#endif

	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask & (1<<PG_LEVEL_2M));
		pfn = end_pfn;
	}

#ifdef CONFIG_X86_64
	/* big page (1G) range */
	start_pfn = round_up(pfn, PFN_DOWN(PUD_SIZE));
	end_pfn = round_down(limit_pfn, PFN_DOWN(PUD_SIZE));
	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask &
				 ((1<<PG_LEVEL_2M)|(1<<PG_LEVEL_1G)));
		pfn = end_pfn;
	}

	/* tail is not big page (1G) alignment */
	start_pfn = round_up(pfn, PFN_DOWN(PMD_SIZE));
	end_pfn = round_down(limit_pfn, PFN_DOWN(PMD_SIZE));
	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask & (1<<PG_LEVEL_2M));
		pfn = end_pfn;
	}
#endif

	/* tail is not big page (2M) alignment */
	start_pfn = pfn;
	end_pfn = limit_pfn;
	nr_range = save_mr(mr, nr_range, start_pfn, end_pfn, 0);

	adjust_range_page_size_mask(mr, nr_range);

	/* try to merge same page size and continuous */
	for (i = 0; nr_range > 1 && i < nr_range - 1; i++) {
		unsigned long old_start;
		if (mr[i].end != mr[i+1].start ||
		    mr[i].page_size_mask != mr[i+1].page_size_mask)
			continue;
		/* move it */
		old_start = mr[i].start;
		memmove(&mr[i], &mr[i+1],
			(nr_range - 1 - i) * sizeof(struct map_range));
		mr[i--].start = old_start;
		nr_range--;
	}

	for (i = 0; i < nr_range; i++)
		pr_debug(" [mem %#010lx-%#010lx] page %s\n",
				mr[i].start, mr[i].end - 1,
				page_size_string(&mr[i]));

	return nr_range;
}

static unsigned long direct_pages_count[PG_LEVEL_NUM];

static void update_page_count(int level, unsigned long pages)
{
	direct_pages_count[level] += pages;
}

void arch_report_meminfo(struct seq_file *m)
{
#ifdef CONFIG_COMP_PROCESSOR
	seq_printf(m, "DirectMap4k:    %8lu kB\n",
			direct_pages_count[PG_LEVEL_4K] << 2);
	seq_printf(m, "DirectMap2M:    %8lu kB\n",
			direct_pages_count[PG_LEVEL_2M] << 11);
	seq_printf(m, "DirectMap1G:    %8lu kB\n",
			direct_pages_count[PG_LEVEL_1G] << 20);
#endif
}

/*
 * Create PTE level page table mapping for physical addresses.
 * It returns the last physical address mapped.
 */
static unsigned long
phys_pte_init(pte_t *pte_page, unsigned long paddr, unsigned long paddr_end,
	      pgprot_t prot)
{
	unsigned long pages = 0, paddr_next;
	unsigned long paddr_last = paddr_end;
	pte_t *pte;
	int i;

	pte = pte_page + pte_index(paddr);
	i = pte_index(paddr);

	for (; i < PTRS_PER_PTE; i++, paddr = paddr_next, pte++) {
		paddr_next = (paddr & PAGE_MASK) + PAGE_SIZE;
		if (paddr >= paddr_end) {
			if (!e820_any_mapped(paddr & PAGE_MASK, paddr_next,
					     E820_RAM) &&
			    !e820_any_mapped(paddr & PAGE_MASK, paddr_next,
					     E820_RESERVED_KERN))
				pte_set(pte, __pte(0));
			continue;
		}

		/*
		 * We will re-use the existing mapping.
		 * Xen for example has some special requirements, like mapping
		 * pagetable pages as RO. So assume someone who pre-setup
		 * these mappings are more intelligent.
		 */
		if (!pte_none(*pte)) {
			pages++;
			continue;
		}

		if (0)
			pr_info("   pte=%p addr=%lx pte=%016lx\n", pte, paddr,
				pfn_pte(paddr >> PAGE_SHIFT, PAGE_KERNEL).pte);
		pages++;
		pte_set(pte, pfn_pte(paddr >> PAGE_SHIFT, prot));
		paddr_last = (paddr & PAGE_MASK) + PAGE_SIZE;
	}

	update_page_count(PG_LEVEL_4K, pages);

	return paddr_last;
}

/*
 * Create PMD level page table mapping for physical addresses. The virtual
 * and physical address have to be aligned at this level.
 * It returns the last physical address mapped.
 */
static unsigned long
phys_pmd_init(pmd_t *pmd_page, unsigned long paddr, unsigned long paddr_end,
	      unsigned long page_size_mask, pgprot_t prot)
{
	unsigned long pages = 0, paddr_next;
	unsigned long paddr_last = paddr_end;

	int i = pmd_index(paddr);

	for (; i < PTRS_PER_PMD; i++, paddr = paddr_next) {
		pmd_t *pmd = pmd_page + pmd_index(paddr);
		pte_t *pte;
		pgprot_t new_prot = prot;

		paddr_next = (paddr & PMD_MASK) + PMD_SIZE;
		if (paddr >= paddr_end) {
			if (!e820_any_mapped(paddr & PMD_MASK, paddr_next,
					     E820_RAM) &&
			    !e820_any_mapped(paddr & PMD_MASK, paddr_next,
					     E820_RESERVED_KERN))
				pmd_set(pmd, __pmd(0));
			continue;
		}

		if (!pmd_none(*pmd)) {
			if (!pmd_large(*pmd)) {
				spin_lock(&init_mm.page_table_lock);
				pte = (pte_t *)pmd_page_vaddr(*pmd);
				paddr_last = phys_pte_init(pte, paddr,
							   paddr_end, prot);
				spin_unlock(&init_mm.page_table_lock);
				continue;
			}
			/*
			 * If we are ok with PG_LEVEL_2M mapping, then we will
			 * use the existing mapping,
			 *
			 * Otherwise, we will split the large page mapping but
			 * use the same existing protection bits except for
			 * large page, so that we don't violate Intel's TLB
			 * Application note (317080) which says, while changing
			 * the page sizes, new and old translations should
			 * not differ with respect to page frame and
			 * attributes.
			 */
			if (page_size_mask & (1 << PG_LEVEL_2M)) {
				pages++;
				paddr_last = paddr_next;
				continue;
			}
			new_prot = pte_pgprot(pte_clrhuge(*(pte_t *)pmd));
		}

		if (page_size_mask & (1<<PG_LEVEL_2M)) {
			pages++;
			spin_lock(&init_mm.page_table_lock);
			pte_set((pte_t *)pmd,
				pfn_pte((paddr & PMD_MASK) >> PAGE_SHIFT,
					__pgprot(pgprot_val(prot) | _PAGE_PSE)));
			spin_unlock(&init_mm.page_table_lock);
			paddr_last = paddr_next;
			continue;
		}

		pte = alloc_low_page();
		paddr_last = phys_pte_init(pte, paddr, paddr_end, new_prot);

		spin_lock(&init_mm.page_table_lock);
		pmd_populate_kernel(&init_mm, pmd, pte);
		spin_unlock(&init_mm.page_table_lock);
	}
	update_page_count(PG_LEVEL_2M, pages);
	return paddr_last;
}

/*
 * Create PUD level page table mapping for physical addresses. The virtual
 * and physical address do not have to be aligned at this level.
 * It returns the last physical address mapped.
 */
static unsigned long
phys_pud_init(pud_t *pud_page, unsigned long paddr, unsigned long paddr_end,
	      unsigned long page_size_mask)
{
	unsigned long pages = 0, paddr_next;
	unsigned long paddr_last = paddr_end;
	unsigned long vaddr = (unsigned long)__va(paddr);
	int i = pud_index(vaddr);

	for (; i < PTRS_PER_PUD; i++, paddr = paddr_next) {
		pud_t *pud;
		pmd_t *pmd;
		pgprot_t prot = PAGE_KERNEL;

		vaddr = (unsigned long)__va(paddr);
		pud = pud_page + pud_index(vaddr);
		paddr_next = (paddr & PUD_MASK) + PUD_SIZE;

		if (paddr >= paddr_end) {
			if (!e820_any_mapped(paddr & PUD_MASK, paddr_next,
					     E820_RAM) &&
			    !e820_any_mapped(paddr & PUD_MASK, paddr_next,
					     E820_RESERVED_KERN))
				pud_set(pud, __pud(0));
			continue;
		}

		if (!pud_none(*pud)) {
			if (!pud_large(*pud)) {
				pmd = pmd_offset(pud, 0);
				paddr_last = phys_pmd_init(pmd, paddr,
							   paddr_end,
							   page_size_mask,
							   prot);
				__flush_tlb_all();
				continue;
			}
			/*
			 * If we are ok with PG_LEVEL_1G mapping, then we will
			 * use the existing mapping.
			 *
			 * Otherwise, we will split the gbpage mapping but use
			 * the same existing protection  bits except for large
			 * page, so that we don't violate Intel's TLB
			 * Application note (317080) which says, while changing
			 * the page sizes, new and old translations should
			 * not differ with respect to page frame and
			 * attributes.
			 */
			if (page_size_mask & (1 << PG_LEVEL_1G)) {
				pages++;
				paddr_last = paddr_next;
				continue;
			}
			prot = pte_pgprot(pte_clrhuge(*(pte_t *)pud));
		}

		if (page_size_mask & (1<<PG_LEVEL_1G)) {
			pages++;
			spin_lock(&init_mm.page_table_lock);
			pte_set((pte_t *)pud,
				pfn_pte((paddr & PUD_MASK) >> PAGE_SHIFT,
					PAGE_KERNEL_LARGE));
			spin_unlock(&init_mm.page_table_lock);
			paddr_last = paddr_next;
			continue;
		}

		pmd = alloc_low_page();
		paddr_last = phys_pmd_init(pmd, paddr, paddr_end,
					   page_size_mask, prot);

		spin_lock(&init_mm.page_table_lock);
		pud_populate(&init_mm, pud, pmd);
		spin_unlock(&init_mm.page_table_lock);
	}
	__flush_tlb_all();

	update_page_count(PG_LEVEL_1G, pages);

	return paddr_last;
}

/*
 * Create page table mapping for the physical memory for specific physical
 * addresses. The virtual and physical addresses have to be aligned on PMD level
 * down. It returns the last physical address mapped.
 */
unsigned long
kernel_physical_mapping_init(unsigned long paddr_start,
			     unsigned long paddr_end,
			     unsigned long page_size_mask)
{
	bool pgd_changed = false;
	unsigned long vaddr, vaddr_start, vaddr_end, vaddr_next, paddr_last;

	paddr_last = paddr_end;
	vaddr = (unsigned long)__va(paddr_start);
	vaddr_end = (unsigned long)__va(paddr_end);
	vaddr_start = vaddr;

	for (; vaddr < vaddr_end; vaddr = vaddr_next) {
		pgd_t *pgd = pgd_offset_k(vaddr);
		pud_t *pud;

		vaddr_next = (vaddr & PGDIR_MASK) + PGDIR_SIZE;

		if (pgd_val(*pgd)) {
			pud = (pud_t *)pgd_page_vaddr(*pgd);
			paddr_last = phys_pud_init(pud, __pa(vaddr),
						   __pa(vaddr_end),
						   page_size_mask);
			continue;
		}

		pud = alloc_low_page();
		paddr_last = phys_pud_init(pud, __pa(vaddr), __pa(vaddr_end),
					   page_size_mask);

		spin_lock(&init_mm.page_table_lock);
		pgd_populate(&init_mm, pgd, pud);
		spin_unlock(&init_mm.page_table_lock);
		pgd_changed = true;
	}

	__flush_tlb_all();

	return paddr_last;
}

/*
 * Setup the direct mapping of the physical memory at PAGE_OFFSET.
 * This runs before bootmem is initialized and gets pages directly from
 * the physical memory. To access them they are temporarily mapped.
 */
unsigned long init_memory_mapping(unsigned long start,
		unsigned long end)
{
	struct map_range mr[NR_RANGE_MR];
	unsigned long ret = 0;
	int nr_range, i;

	pr_debug("init_memory_mapping: [mem %#010lx-%#010lx]\n",
	       start, end - 1);

	memset(mr, 0, sizeof(mr));
	nr_range = split_mem_range(mr, 0, start, end);

	for (i = 0; i < nr_range; i++)
		ret = kernel_physical_mapping_init(mr[i].start, mr[i].end,
						   mr[i].page_size_mask);

	max_pfn_mapped = max(max_pfn_mapped, ret >> PAGE_SHIFT);

	return ret >> PAGE_SHIFT;
}

/*
 * We need to iterate through the E820 memory map and create direct mappings
 * for only E820_RAM and E820_KERN_RESERVED regions. We cannot simply
 * create direct mappings for all pfns from [0 to max_low_pfn) and
 * [4GB to max_pfn) because of possible memory holes in high addresses
 * that cannot be marked as UC by fixed/variable range MTRRs.
 * Depending on the alignment of E820 ranges, this may possibly result
 * in using smaller size (i.e. 4K instead of 2M or 1G) page tables.
 *
 * init_mem_mapping() calls init_range_memory_mapping() with big range.
 * That range would have hole in the middle or ends, and only ram parts
 * will be mapped in init_range_memory_mapping().
 */
static unsigned long __init init_range_memory_mapping(
					   unsigned long r_start,
					   unsigned long r_end)
{
	unsigned long start_pfn, end_pfn;
	unsigned long mapped_ram_size = 0;
	int i;

	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, NULL) {
		u64 start = clamp_val(PFN_PHYS(start_pfn), r_start, r_end);
		u64 end = clamp_val(PFN_PHYS(end_pfn), r_start, r_end);
		if (start >= end)
			continue;

		/*
		 * If it is overlapping with brk pgt, we need to
		 * alloc pgt buf from memblock instead.
		 */
		can_use_brk_pgt = max(start, (u64)pgt_buf_end<<PAGE_SHIFT) >=
				    min(end, (u64)pgt_buf_top<<PAGE_SHIFT);
		init_memory_mapping(start, end);
		mapped_ram_size += end - start;
		can_use_brk_pgt = true;
	}

	pr_info("max_pfn_mapped: %#lx -> 0x%p\n", max_pfn_mapped,
		__va(max_pfn_mapped<<PAGE_SHIFT));
	return mapped_ram_size;
}

static unsigned long __init get_new_step_size(unsigned long step_size)
{
	/*
	 * Initial mapped size is PMD_SIZE (2M).
	 * We can not set step_size to be PUD_SIZE (1G) yet.
	 * In worse case, when we cross the 1G boundary, and
	 * PG_LEVEL_2M is not set, we will need 1+1+512 pages (2M + 8k)
	 * to map 1G range with PTE. Hence we use one less than the
	 * difference of page table level shifts.
	 *
	 * Don't need to worry about overflow in the top-down case, on 32bit,
	 * when step_size is 0, round_down() returns 0 for start, and that
	 * turns it into 0x100000000ULL.
	 * In the bottom-up case, round_up(x, 0) returns 0 though too, which
	 * needs to be taken into consideration by the code below.
	 */
	return step_size << (PMD_SHIFT - PAGE_SHIFT - 1);
}

/**
 * memory_map_top_down - Map [map_start, map_end) top down
 * @map_start: start address of the target memory range
 * @map_end: end address of the target memory range
 *
 * This function will setup direct mapping for memory range
 * [map_start, map_end) in top-down. That said, the page tables
 * will be allocated at the end of the memory, and we map the
 * memory in top-down.
 */
static void __init memory_map_top_down(unsigned long map_start,
				       unsigned long map_end)
{
	unsigned long real_end, start, last_start;
	unsigned long step_size;
	unsigned long addr;
	unsigned long mapped_ram_size = 0;

	/* xen has big range in reserved near end of ram, skip it at first.*/
	addr = memblock_find_in_range(map_start, map_end, PMD_SIZE, PMD_SIZE);
	real_end = addr + PMD_SIZE;

	/* step_size need to be small so pgt_buf from BRK could cover it */
	step_size = PMD_SIZE;

	/* will get exact value next */
	max_pfn_mapped = 0;
	min_pfn_mapped = real_end >> PAGE_SHIFT;
	last_start = start = real_end;

	/*
	 * We start from the top (end of memory) and go to the bottom.
	 * The memblock_find_in_range() gets us a block of RAM from the
	 * end of RAM in [min_pfn_mapped, max_pfn_mapped) used as new pages
	 * for page table.
	 */
	while (last_start > map_start) {
		if (last_start > step_size) {
			start = round_down(last_start - 1, step_size);
			if (start < map_start)
				start = map_start;
		} else
			start = map_start;
		mapped_ram_size += init_range_memory_mapping(start,
							last_start);
		last_start = start;
		min_pfn_mapped = last_start >> PAGE_SHIFT;
		if (mapped_ram_size >= step_size)
			step_size = get_new_step_size(step_size);
	}

	if (real_end < map_end)
		init_range_memory_mapping(real_end, map_end);
}

void __init init_mem_mapping(void)
{
	unsigned long end;

	probe_page_size_mask();

	end = max_pfn << PAGE_SHIFT;

	/* the ISA range is always mapped regardless of memory holes */
	init_memory_mapping(0, ISA_END_ADDRESS);

	/*
	 * X86 maps top->down direction
	 */
	memory_map_top_down(ISA_END_ADDRESS, end);

	load_cr3(swapper_pg_dir);
	__flush_tlb_all();
}

void __init arch_zone_init(void) {
	unsigned long max_zone_pfns[MAX_NR_ZONES];

	memset(max_zone_pfns, 0, sizeof(max_zone_pfns));

#ifdef CONFIG_ZONE_DMA
	max_zone_pfns[ZONE_DMA]		= min(MAX_DMA_PFN, max_pfn);
#endif

#ifdef CONFIG_ZONE_DMA32
	max_zone_pfns[ZONE_DMA32]	= min(MAX_DMA32_PFN, max_pfn);
#endif

	max_zone_pfns[ZONE_NORMAL]	= max_pfn;

	free_area_init_nodes(max_zone_pfns);
}

#ifdef CONFIG_SPARSEMEM_VMEMMAP
/*
 * Initialise the sparsemem vmemmap using huge-pages at the PMD level.
 */
static long addr_start, addr_end;
static void *p_start, *p_end;
static int node_start;

static int __init
vmemmap_populate_hugepages(unsigned long start, unsigned long end, int node)
{
	unsigned long addr;
	unsigned long next;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	for (addr = start; addr < end; addr = next) {
		next = pmd_addr_end(addr, end);

		pgd = vmemmap_pgd_populate(addr, node);
		if (!pgd)
			return -ENOMEM;

		pud = vmemmap_pud_populate(pgd, addr, node);
		if (!pud)
			return -ENOMEM;

		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd)) {
			void *p;

			p = __vmemmap_alloc_block_buf(PMD_SIZE, node);
			if (p) {
				pte_t entry;

				entry = pfn_pte(__pa(p) >> PAGE_SHIFT,
						PAGE_KERNEL_LARGE);
				pmd_set(pmd, __pmd(pte_val(entry)));

				/* check to see if we have contiguous blocks */
				if (p_end != p || node_start != node) {
					if (p_start)
						pr_debug(" [%lx-%lx] PMD -> [%p-%p] on node %d\n",
						       addr_start, addr_end-1, p_start, p_end-1, node_start);
					addr_start = addr;
					node_start = node;
					p_start = p;
				}

				addr_end = addr + PMD_SIZE;
				p_end = p + PMD_SIZE;
				continue;
			}
		} else if (pmd_large(*pmd)) {
			vmemmap_verify((pte_t *)pmd, node, addr, next);
			continue;
		}
		pr_warn_once("vmemmap: falling back to regular page backing\n");
		if (vmemmap_populate_basepages(addr, next, node))
			return -ENOMEM;
	}
	return 0;
}

int __init vmemmap_populate(unsigned long start, unsigned long end, int node)
{
	int err;

	if (cpu_has(X86_FEATURE_PSE))
		err = vmemmap_populate_hugepages(start, end, node);
	else
		err = vmemmap_populate_basepages(start, end, node);

#if 0
	if (!err)
		sync_global_pgds(start, end - 1);
#endif
	return err;
}
#endif /* CONFIG_SPARSEMEM_VMEMMAP */
