/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


#include <asm/asm.h>
#include <asm/e820.h>
#include <asm/page.h>
#include <asm/setup.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>

#include <lego/mm.h>
#include <lego/numa.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/memblock.h>
#include <lego/list.h>

DEFINE_SPINLOCK(pgd_lock);
LIST_HEAD(pgd_list);

int after_bootmem;
static unsigned long __initdata pgt_buf_start;
static unsigned long __initdata pgt_buf_end;
static unsigned long __initdata pgt_buf_top;
static bool __initdata can_use_brk_pgt = true;

static unsigned long min_pfn_mapped;

/*
 * Pages returned are already directly mapped.
 *
 * Changing that is likely to break Xen, see commit:
 *
 *    279b706 x86,xen: introduce x86_init.mapping.pagetable_reserve
 *
 * for detailed information.
 */
void *alloc_low_pages(unsigned int num)
{
	unsigned long pfn;
	int i;

#if 0
	if (after_bootmem) {
		unsigned int order;

		order = get_order((unsigned long)num << PAGE_SHIFT);
		return (void *)__get_free_pages(GFP_ATOMIC | __GFP_NOTRACK |
						__GFP_ZERO, order);
	}
#endif

	pr_debug("alloc_low_pages min_pfn_mapped %lx max_pfn_mapped %lx pgt_buf_end %lx pgt_buf_top %lx can_use_brk_pgt %d\n",
			min_pfn_mapped, max_pfn_mapped, pgt_buf_end, pgt_buf_top, can_use_brk_pgt);
	if ((pgt_buf_end + num) > pgt_buf_top || !can_use_brk_pgt) {
		unsigned long ret;
		if (min_pfn_mapped >= max_pfn_mapped)
			panic("alloc_low_pages: ran out of memory");
		ret = memblock_find_in_range(min_pfn_mapped << PAGE_SHIFT,
					max_pfn_mapped << PAGE_SHIFT,
					PAGE_SIZE * num , PAGE_SIZE);
		if (!ret)
			panic("alloc_low_pages: can not alloc memory");
		pr_debug("got memblock ret %lx\n", ret);
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
		pr_debug("alloc_low_pages pfn %lx adr %p\n", pfn, adr);
		clear_page(adr);
		pr_debug("alloc_low_pages exit pfn %lx adr %p\n", pfn, adr);
	}

	return __va(pfn << PAGE_SHIFT);
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

	base = __pa_kernel(extend_brk(tables, PAGE_SIZE));

	pgt_buf_start = base >> PAGE_SHIFT;
	pgt_buf_end = pgt_buf_start;
	pgt_buf_top = pgt_buf_start + (tables >> PAGE_SHIFT);
}

struct map_range {
	unsigned long start;
	unsigned long end;
	unsigned page_size_mask;
};
#define NR_RANGE_MR 5

static int page_size_mask;

/*
 * TODO:
 * Using 4KB for now; May switch to 1GB later
 */
static void __init probe_page_size_mask(void)
{
	page_size_mask |= 1 << PG_LEVEL_4K;
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
	end_pfn = round_up(pfn, PFN_DOWN(PMD_SIZE));

	if (end_pfn > limit_pfn)
		end_pfn = limit_pfn;
	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn, 0);
		pfn = end_pfn;
	}

	/* big page (2M) range */
	start_pfn = round_up(pfn, PFN_DOWN(PMD_SIZE));
	end_pfn = round_up(pfn, PFN_DOWN(PUD_SIZE));
	if (end_pfn > round_down(limit_pfn, PFN_DOWN(PMD_SIZE)))
		end_pfn = round_down(limit_pfn, PFN_DOWN(PMD_SIZE));

	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask & (1<<PG_LEVEL_2M));
		pfn = end_pfn;
	}

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

/*
 * Create PTE level page table mapping for physical addresses.
 * It returns the last physical address mapped.
 */
static unsigned long phys_pte_init(pte_t *pte_page, unsigned long paddr, unsigned long paddr_end,
	      pgprot_t prot)
{
	unsigned long paddr_next;
	unsigned long paddr_last = paddr_end;
	pte_t *pte;
	int i;

	pr_debug("phys_pte_init pmd_page %p\n", pte_page);
	pte = pte_page + pte_index(paddr);
	i = pte_index(paddr);

	for (; i < PTRS_PER_PTE; i++, paddr = paddr_next, pte++) {
		paddr_next = (paddr & PAGE_MASK) + PAGE_SIZE;
		if (paddr >= paddr_end) {
			if (!after_bootmem &&
			    !e820_any_mapped(paddr & PAGE_MASK, paddr_next,
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
			continue;
		}

		if (0)
			pr_info("   pte=%p addr=%lx pte=%016lx\n", pte, paddr,
				pfn_pte(paddr >> PAGE_SHIFT, PAGE_KERNEL).pte);
		pte_set(pte, pfn_pte(paddr >> PAGE_SHIFT, prot));
		paddr_last = (paddr & PAGE_MASK) + PAGE_SIZE;
	}

	pr_debug("phys_pte_init exit paddr_last %lx\n", paddr_last);
	return paddr_last;
}

/*
 * Create PMD level page table mapping for physical addresses. The virtual
 * and physical address have to be aligned at this level.
 * It returns the last physical address mapped.
 */
static unsigned long phys_pmd_init(pmd_t *pmd_page, unsigned long paddr, unsigned long paddr_end,
	      unsigned long page_size_mask, pgprot_t prot)
{
	unsigned long paddr_next;
	unsigned long paddr_last = paddr_end;

	int i = pmd_index(paddr);

	pr_debug("phys_pmd_init pmd_page %p\n", pmd_page);
	for (; i < PTRS_PER_PMD; i++, paddr = paddr_next) {
		pmd_t *pmd = pmd_page + pmd_index(paddr);
		pte_t *pte;
		pgprot_t new_prot = prot;

		paddr_next = (paddr & PMD_MASK) + PMD_SIZE;
		if (paddr >= paddr_end) {
			if (!after_bootmem &&
			    !e820_any_mapped(paddr & PMD_MASK, paddr_next,
					     E820_RAM) &&
			    !e820_any_mapped(paddr & PMD_MASK, paddr_next,
					     E820_RESERVED_KERN))
				pmd_set(pmd, __pmd(0));
			continue;
		}

		if (!pmd_none(*pmd)) {
			if (!pmd_large(*pmd)) {
				pr_debug("pmd not none not large\n");
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
				paddr_last = paddr_next;
				continue;
			}
			pr_debug("pmd not none\n");
			new_prot = pte_pgprot(pte_clrhuge(*(pte_t *)pmd));
		}

		if (page_size_mask & (1<<PG_LEVEL_2M)) {
			spin_lock(&init_mm.page_table_lock);
			pte_set((pte_t *)pmd,
				pfn_pte((paddr & PMD_MASK) >> PAGE_SHIFT,
					__pgprot(pgprot_val(prot) | _PAGE_PSE)));
			spin_unlock(&init_mm.page_table_lock);
			paddr_last = paddr_next;
			continue;
		}

		pte = alloc_low_pages(1);
		pr_debug("phy_pmd_init allocated one after phys_pte_init\n");
		paddr_last = phys_pte_init(pte, paddr, paddr_end, new_prot);

		spin_lock(&init_mm.page_table_lock);
		pmd_populate_kernel(&init_mm, pmd, pte);
		spin_unlock(&init_mm.page_table_lock);
	}

	pr_debug("phys_pmd_init exit paddr_last %lx\n", paddr_last);
	return paddr_last;
}

/*
 * Create PUD level page table mapping for physical addresses. The virtual
 * and physical address do not have to be aligned at this level. KASLR can
 * randomize virtual addresses up to this level.
 * It returns the last physical address mapped.
 */
static unsigned long phys_pud_init(pud_t *pud_page, unsigned long paddr, 
		unsigned long paddr_end,
		unsigned long page_size_mask)
{
	unsigned long paddr_next;
	unsigned long paddr_last = paddr_end;
	unsigned long vaddr = (unsigned long)__va(paddr);
	int i = pud_index(vaddr);

	pr_debug("phys_pud_init pud_page %p, paddr %lx, paddr_end %lx\n",
			pud_page, paddr, paddr_end);
	for (; i < PTRS_PER_PUD; i++, paddr = paddr_next) {
		pud_t *pud;
		pmd_t *pmd;
		pgprot_t prot = PAGE_KERNEL;

		vaddr = (unsigned long)__va(paddr);
		pud = pud_page + pud_index(vaddr);
		paddr_next = (paddr & PUD_MASK) + PUD_SIZE;

		pr_debug("pud %lx\n", pud);
		if (paddr >= paddr_end) {
			if (!after_bootmem &&
			    !e820_any_mapped(paddr & PUD_MASK, paddr_next,
					     E820_RAM) &&
			    !e820_any_mapped(paddr & PUD_MASK, paddr_next,
					     E820_RESERVED_KERN))
				pud_set(pud, __pud(0));
			continue;
		}

		if (!pud_none(*pud)) {
			if (!pud_large(*pud)) {
				pr_debug("pud not none not large\n");
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
				paddr_last = paddr_next;
				continue;
			}
			prot = pte_pgprot(pte_clrhuge(*(pte_t *)pud));
		}

		if (page_size_mask & (1<<PG_LEVEL_1G)) {
			spin_lock(&init_mm.page_table_lock);
			pte_set((pte_t *)pud,
				pfn_pte((paddr & PUD_MASK) >> PAGE_SHIFT,
					PAGE_KERNEL_LARGE));
			spin_unlock(&init_mm.page_table_lock);
			paddr_last = paddr_next;
			continue;
		}

		pmd = alloc_low_pages(1);
		pr_debug("phys_pud_init allocated one\n");
		paddr_last = phys_pmd_init(pmd, paddr, paddr_end,
					   page_size_mask, prot);

		spin_lock(&init_mm.page_table_lock);
		pud_populate(&init_mm, pud, pmd);
		spin_unlock(&init_mm.page_table_lock);
	}
	__flush_tlb_all();
	pr_debug("phys_pmd_init exit\n");

	return paddr_last;
}

/*
 * When memory was added/removed make sure all the processes MM have
 * suitable PGD entries in the local PGD level page.
 */
void sync_global_pgds(unsigned long start, unsigned long end, int removed)
{

// TODO
#if 0
	unsigned long address;

	for (address = start; address <= end; address += PGDIR_SIZE) {
		const pgd_t *pgd_ref = pgd_offset_k(address);
		struct page *page;

		/*
		 * When it is called after memory hot remove, pgd_none()
		 * returns true. In this case (removed == 1), we must clear
		 * the PGD entries in the local PGD level page.
		 */
		if (pgd_none(*pgd_ref) && !removed)
			continue;

		spin_lock(&pgd_lock);
		list_for_each_entry(page, &pgd_list, lru) {
			pgd_t *pgd;

			pgd = (pgd_t *)page_address(page) + pgd_index(address);

			if (!pgd_none(*pgd_ref) && !pgd_none(*pgd))
				BUG_ON(pgd_page_vaddr(*pgd)
				       != pgd_page_vaddr(*pgd_ref));

			if (removed) {
				if (pgd_none(*pgd_ref) && !pgd_none(*pgd))
					pgd_clear(pgd);
			} else {
				if (pgd_none(*pgd))
					pgd_set(pgd, *pgd_ref);
			}

		}
		spin_unlock(&pgd_lock);
	}
#endif
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
	pr_debug("kernel_physical_mapping_init phys [%#010lx-%#010lx] virt [%#010lx-%#010lx]\n", 
			paddr_start, paddr_end, vaddr_start, vaddr_end);

	for (; vaddr < vaddr_end; vaddr = vaddr_next) {
		pgd_t *pgd = pgd_offset_k(vaddr);
		pud_t *pud;

		vaddr_next = (vaddr & PGDIR_MASK) + PGDIR_SIZE;

		pr_debug("pgd %p vaddr %lx vaddr_next %lx PGDIR_MASK %lx PGDIR_SIZE %lx %lx\n", 
			pgd, vaddr, vaddr_next, PGDIR_MASK, PGDIR_SIZE, vaddr & PGDIR_MASK);
		if (pgd_val(*pgd)) {
			pr_debug("pgd exist\n");
			pud = (pud_t *)pgd_page_vaddr(*pgd);
			paddr_last = phys_pud_init(pud, __pa(vaddr),
						   __pa(vaddr_end),
						   page_size_mask);
			continue;
		}

		pud = alloc_low_pages(1);
		pr_debug("kernel_physical_mapping_init allocated one\n");
		paddr_last = phys_pud_init(pud, __pa(vaddr), __pa(vaddr_end),
					   page_size_mask);

		spin_lock(&init_mm.page_table_lock);
		pgd_populate(&init_mm, pgd, pud);
		spin_unlock(&init_mm.page_table_lock);
		pgd_changed = true;
	}

	if (pgd_changed)
		sync_global_pgds(vaddr_start, vaddr_end - 1, 0);

	__flush_tlb_all();

	return paddr_last;
}

struct range {
	u64   start;
	u64   end;
};

int add_range(struct range *range, int az, int nr_range, u64 start, u64 end)
{
	if (start >= end)
		return nr_range;

	/* Out of slots: */
	if (nr_range >= az)
		return nr_range;

	range[nr_range].start = start;
	range[nr_range].end = end;

	nr_range++;

	return nr_range;
}

int add_range_with_merge(struct range *range, int az, int nr_range,
		u64 start, u64 end)
{
	int i;

	if (start >= end)
		return nr_range;

	/* get new start/end: */
	for (i = 0; i < nr_range; i++) {
		u64 common_start, common_end;

		if (!range[i].end)
			continue;

		common_start = max(range[i].start, start);
		common_end = min(range[i].end, end);
		if (common_start > common_end)
			continue;

		/* new start/end, will add it back at last */
		start = min(range[i].start, start);
		end = max(range[i].end, end);

		memmove(&range[i], &range[i + 1],
				(nr_range - (i + 1)) * sizeof(range[i]));
		range[nr_range - 1].start = 0;
		range[nr_range - 1].end   = 0;
		nr_range--;
		i--;
	}

	/* Need to add it: */
	return add_range(range, az, nr_range, start, end);
}

static int cmp_range(const void *x1, const void *x2)
{
	const struct range *r1 = x1;
	const struct range *r2 = x2;

	if (r1->start < r2->start)
		return -1;
	if (r1->start > r2->start)
		return 1;
	return 0;
}

int clean_sort_range(struct range *range, int az)
{
	int i, j, k = az - 1, nr_range = az;

	for (i = 0; i < k; i++) {
		if (range[i].end)
			continue;
		for (j = k; j > i; j--) {
			if (range[j].end) {
				k = j;
				break;
			}
		}
		if (j == i)
			break;
		range[i].start = range[k].start;
		range[i].end   = range[k].end;
		range[k].start = 0;
		range[k].end   = 0;
		k--;
	}
	/* count it */
	for (i = 0; i < az; i++) {
		if (!range[i].end) {
			nr_range = i;
			break;
		}
	}

	/* sort them */
	sort(range, nr_range, sizeof(struct range), cmp_range, NULL);

	return nr_range;
}

struct range pfn_mapped[E820MAX];
int nr_pfn_mapped;

static void add_pfn_range_mapped(unsigned long start_pfn, unsigned long end_pfn)                                                                                                     
{       
	nr_pfn_mapped = add_range_with_merge(pfn_mapped, E820MAX,
			nr_pfn_mapped, start_pfn, end_pfn);                                                                                                     
	nr_pfn_mapped = clean_sort_range(pfn_mapped, E820MAX); 

	max_pfn_mapped = max(max_pfn_mapped, end_pfn);

	if (start_pfn < (1UL<<(32-PAGE_SHIFT)))
		max_low_pfn_mapped = max(max_low_pfn_mapped,
				min(end_pfn, 1UL<<(32-PAGE_SHIFT)));
	pr_debug("add_pfn_range_mapped start_pfn %lx end_pfn %lx nr_pfn_mapped %lx max_pfn_mapped %lx max_low_pfn_mapped %lx\n",
			start_pfn, end_pfn, nr_pfn_mapped, max_pfn_mapped, max_low_pfn_mapped);
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

	add_pfn_range_mapped(start >> PAGE_SHIFT, ret >> PAGE_SHIFT);

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

	pr_debug("init_range_memory_mapping [mem %#010lx-%#010lx]\n",
			r_start, r_end);
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

	pr_debug("memory_map_top_down [%#010lx-%#010lx] addr %lx min_pfn_mapped %lx real_end %lx addr %lx PMD_SIZE %lx\n",
			map_start, map_end, addr, min_pfn_mapped, real_end, addr, PMD_SIZE);
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

#if 0
void __init mem_init(void)
{
	pci_iommu_alloc();

	/* clear_bss() already clear the empty_zero_page */

	register_page_bootmem_info();

	/* this will put all memory onto the freelists */
	free_all_bootmem();
	after_bootmem = 1;

	mem_init_print_info(NULL);
}
#endif

void __init init_mem_mapping(void)
{
	unsigned long end, pgd;

	probe_page_size_mask();

	end = max_pfn << PAGE_SHIFT;

	init_memory_mapping(0, ISA_END_ADDRESS);

	/*
	 * X86 maps top->down direction
	 */
	memory_map_top_down(ISA_END_ADDRESS, end);

	if (max_pfn > max_low_pfn)
		max_low_pfn = max_pfn;

	printk(KERN_ERR "%s: init_level4_pgt  is %lx\n", __func__, __pa(init_level4_pgt));
	pgd = read_cr3();
	printk(KERN_ERR "%s: current cr3 is %lx\n", __func__, pgd);
	write_cr3(__pa(swapper_pg_dir));
	pgd = read_cr3();
	printk(KERN_ERR "%s: cr3 is set  to %lx\n", __func__, pgd);
	__flush_tlb_all();
}
