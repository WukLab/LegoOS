/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MM_H_
#define _LEGO_MM_H_

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/segment.h>
#include <asm/processor.h>

#include <lego/pfn.h>
#include <lego/atomic.h>
#include <lego/kernel.h>
#include <lego/nodemask.h>

/* MUST list before others */
#include <lego/page-flags-layout.h>

#include <lego/mm_zone.h>
#include <lego/mm_types.h>
#include <lego/mm_debug.h>
#include <lego/mmap.h>
#include <lego/memory_model.h>
#include <lego/page-flags.h>
#include <lego/gfp.h>

/* Page flags: | [SECTION] | [NODE] | ZONE | [LAST_CPUPID] | ... | FLAGS | */
#define SECTIONS_PGOFF		((sizeof(unsigned long)*8) - SECTIONS_WIDTH)
#define NODES_PGOFF		(SECTIONS_PGOFF - NODES_WIDTH)
#define ZONES_PGOFF		(NODES_PGOFF - ZONES_WIDTH)
#define LAST_CPUPID_PGOFF	(ZONES_PGOFF - LAST_CPUPID_WIDTH)

/*
 * Define the bit shifts to access each section.  For non-existent
 * sections we define the shift as 0; that plus a 0 mask ensures
 * the compiler will optimise away reference to them.
 */
#define SECTIONS_PGSHIFT	(SECTIONS_PGOFF * (SECTIONS_WIDTH != 0))
#define NODES_PGSHIFT		(NODES_PGOFF * (NODES_WIDTH != 0))
#define ZONES_PGSHIFT		(ZONES_PGOFF * (ZONES_WIDTH != 0))
#define LAST_CPUPID_PGSHIFT	(LAST_CPUPID_PGOFF * (LAST_CPUPID_WIDTH != 0))

/* NODE:ZONE or SECTION:ZONE is used to ID a zone for the buddy allocator */
#ifdef NODE_NOT_IN_PAGE_FLAGS
#define ZONEID_SHIFT		(SECTIONS_SHIFT + ZONES_SHIFT)
#define ZONEID_PGOFF		((SECTIONS_PGOFF < ZONES_PGOFF)? \
						SECTIONS_PGOFF : ZONES_PGOFF)
#else
#define ZONEID_SHIFT		(NODES_SHIFT + ZONES_SHIFT)
#define ZONEID_PGOFF		((NODES_PGOFF < ZONES_PGOFF)? \
						NODES_PGOFF : ZONES_PGOFF)
#endif

#define ZONEID_PGSHIFT		(ZONEID_PGOFF * (ZONEID_SHIFT != 0))

#if SECTIONS_WIDTH+NODES_WIDTH+ZONES_WIDTH > BITS_PER_LONG - NR_PAGEFLAGS
#error SECTIONS_WIDTH+NODES_WIDTH+ZONES_WIDTH > BITS_PER_LONG - NR_PAGEFLAGS
#endif

#define ZONES_MASK		((1UL << ZONES_WIDTH) - 1)
#define NODES_MASK		((1UL << NODES_WIDTH) - 1)
#define SECTIONS_MASK		((1UL << SECTIONS_WIDTH) - 1)
#define LAST_CPUPID_MASK	((1UL << LAST_CPUPID_SHIFT) - 1)
#define ZONEID_MASK		((1UL << ZONEID_SHIFT) - 1)

#if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
#define SECTION_IN_PAGE_FLAGS
#endif

#ifdef SECTION_IN_PAGE_FLAGS
static inline void set_page_section(struct page *page, unsigned long section)
{
	page->flags &= ~(SECTIONS_MASK << SECTIONS_PGSHIFT);
	page->flags |= (section & SECTIONS_MASK) << SECTIONS_PGSHIFT;
}

static inline unsigned long page_to_section(const struct page *page)
{
	return (page->flags >> SECTIONS_PGSHIFT) & SECTIONS_MASK;
}
#endif

static inline enum zone_type page_to_zonetype(const struct page *page)
{
	return (page->flags >> ZONES_PGSHIFT) & ZONES_MASK;
}

/*
 * The identification function is mainly used by the buddy allocator for
 * determining if two pages could be buddies.
 *
 * We only guarantee that it will return the same value for two combinable
 * pages in a zone.
 */
static inline int page_zone_id(struct page *page)
{
	return (page->flags >> ZONEID_PGSHIFT) & ZONEID_MASK;
}

static inline int zone_to_nid(struct zone *zone)
{
#ifdef CONFIG_NUMA
	return zone->node;
#else
	return 0;
#endif
}

static inline int page_to_nid(const struct page *page)
{
	return (page->flags >> NODES_PGSHIFT) & NODES_MASK;
}

static inline struct zone *page_zone(const struct page *page)
{
	enum zone_type type = page_to_zonetype(page);

	return &NODE_DATA(page_to_nid(page))->node_zones[type];
}

static inline pg_data_t *page_pgdat(const struct page *page)
{
	return NODE_DATA(page_to_nid(page));
}

static inline void set_page_zone(struct page *page, enum zone_type zone)
{
	page->flags &= ~(ZONES_MASK << ZONES_PGSHIFT);
	page->flags |= (zone & ZONES_MASK) << ZONES_PGSHIFT;
}

static inline void set_page_node(struct page *page, unsigned long node)
{
	page->flags &= ~(NODES_MASK << NODES_PGSHIFT);
	page->flags |= (node & NODES_MASK) << NODES_PGSHIFT;
}

static inline void set_page_links(struct page *page, enum zone_type zone,
				unsigned long node, unsigned long pfn)
{
	set_page_zone(page, zone);
	set_page_node(page, node);
#ifdef SECTION_IN_PAGE_FLAGS
	set_page_section(page, pfn_to_section_nr(pfn));
#endif
}

#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr)	ALIGN(addr, PAGE_SIZE)

/* highest direct mapped pfn */
extern unsigned long max_pfn_mapped;

/* highest pfn of this machine */
extern unsigned long max_pfn;

/* Defined in mm/page_alloc.c */
extern unsigned long totalram_pages;
extern unsigned long totalreserve_pages;

/* Defined in mm/init-mm.c */
extern struct mm_struct init_mm;

void __init free_area_init_nodes(unsigned long *max_zone_pfn);

void __init sparse_init(void);
void __init arch_zone_init(void);
void __init memory_init(void);
void __init memory_present(int nid, unsigned long start, unsigned long end);

void sparse_mem_maps_populate_node(struct page **map_map,
				   unsigned long pnum_begin,
				   unsigned long pnum_end,
				   unsigned long map_count,
				   int nodeid);
struct page *sparse_mem_map_populate(unsigned long pnum, int nid);
int vmemmap_populate(unsigned long start, unsigned long end, int node);
void vmemmap_populate_print_last(void);
int vmemmap_populate_basepages(unsigned long start, unsigned long end, int node);
pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
pud_t *vmemmap_pud_populate(pgd_t *pgd, unsigned long addr, int node);
pmd_t *vmemmap_pmd_populate(pud_t *pud, unsigned long addr, int node);
pte_t *vmemmap_pte_populate(pmd_t *pmd, unsigned long addr, int node);
void *__vmemmap_alloc_block_buf(unsigned long size, int node);
void vmemmap_verify(pte_t *, int, unsigned long, unsigned long);

#define page_private(page)		((page)->private)
#define set_page_private(page, v)	((page)->private = (v))

#ifdef CONFIG_FLATMEM
static inline int pfn_valid(unsigned long pfn)
{
	return pfn < max_pfn;
}
#endif

static inline void set_page_count(struct page *page, int v)
{
	atomic_set(&page->_refcount, v);
}

/*
 * Setup the page count before being freed into the page allocator for
 * the first time (boot or memory hotplug)
 */
static inline void init_page_count(struct page *page)
{
	set_page_count(page, 1);
}

/*
 * Turn a non-refcounted page (->_refcount == 0) into refcounted with
 * a count of one.
 */
static inline void set_page_refcounted(struct page *page)
{
	set_page_count(page, 1);
}

/*
 * The atomic page->_mapcount, starts from -1: so that transitions
 * both from it and to it can be tracked, using atomic_inc_and_test
 * and atomic_add_negative(-1).
 */
static inline void page_mapcount_reset(struct page *page)
{
	atomic_set(&(page)->_mapcount, -1);
}

static inline int page_ref_count(struct page *page)
{
	return atomic_read(&page->_refcount);
}

/*
 * Drop a ref, return true if the refcount fell to zero (the page has no users)
 */
static inline int put_page_testzero(struct page *page)
{
	VM_BUG_ON_PAGE(page_ref_count(page) == 0, page);
	return atomic_dec_and_test(&page->_refcount);
}

static inline void get_page(struct page *page)
{
	VM_BUG_ON_PAGE(page_ref_count(page) <= 0, page);
	atomic_inc(&page->_refcount);
}

/*
 * This function returns the order of a free page in the buddy system. In
 * general, page_zone(page)->lock must be held by the caller to prevent the
 * page from being allocated in parallel and returning garbage as the order.
 * If a caller does not hold page_zone(page)->lock, it must guarantee that the
 * page cannot be allocated or merged in parallel. Alternatively, it must
 * handle invalid values gracefully, and use page_order_unsafe() below.
 */
static inline unsigned int page_order(struct page *page)
{
	/* PageBuddy() must be checked by the caller */
	return page_private(page);
}

/*
 * Like page_order(), but for callers who cannot afford to hold the zone lock.
 * PageBuddy() should be checked first by the caller to minimize race window,
 * and invalid values must be handled gracefully.
 *
 * READ_ONCE is used so that if the caller assigns the result into a local
 * variable and e.g. tests it for valid range before using, the compiler cannot
 * decide to remove the variable and inline the page_private(page) multiple
 * times, potentially observing different values in the tests and the actual
 * use of the result.
 */
#define page_order_unsafe(page)		READ_ONCE(page_private(page))

void reserve_bootmem_region(phys_addr_t start, phys_addr_t end);

void __free_pages_bootmem(struct page *page, unsigned long pfn,
			unsigned int order);

void __free_pages(struct page *page, unsigned int order);
void free_pages(unsigned long addr, unsigned int order);

#define __free_page(page) __free_pages((page), 0)
#define free_page(addr) free_pages((addr), 0)

/*
 * We get the zone list from the current node and the gfp_mask.
 * This zone list contains a maximum of MAXNODES*MAX_NR_ZONES zones.
 * There are two zonelists per node, one for all zones with memory and
 * one containing just zones from the node the zonelist belongs to.
 */
static inline struct zonelist *node_zonelist(int nid, gfp_t flags)
{
	return NODE_DATA(nid)->node_zonelists + gfp_zonelist(flags);
}

struct page *
__alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order,
		       struct zonelist *zonelist, nodemask_t *nodemask);

static __always_inline struct page *
__alloc_pages(gfp_t gfp_mask, unsigned int order,
		struct zonelist *zonelist)
{
	return __alloc_pages_nodemask(gfp_mask, order, zonelist, NULL);
}

/*
 * Allocate pages, preferring the node given as nid. The node must be valid and
 * online. For more general interface, see alloc_pages_node().
 */
static __always_inline struct page *
__alloc_pages_node(int nid, gfp_t gfp_mask, unsigned int order)
{
	/*
	 * If these messages show up, means there are
	 * some major problems with the kernel.
	 */
	VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES);
	VM_WARN_ON(!node_online(nid));

	return __alloc_pages(gfp_mask, order, node_zonelist(nid, gfp_mask));
}

/*
 * Allocate pages, preferring the node given as nid. When nid == NUMA_NO_NODE,
 * prefer the current CPU's closest node. Otherwise node must be valid and
 * online.
 */
static __always_inline struct page *
alloc_pages_node(int nid, gfp_t gfp_mask, unsigned int order)
{
	if (nid == NUMA_NO_NODE)
		nid = smp_node_id();
	return __alloc_pages_node(nid, gfp_mask, order);
}

#define alloc_pages(gfp_mask, order)	alloc_pages_node(smp_node_id(), gfp_mask, order)
#define _alloc_page(gfp_mask)		alloc_pages(gfp_mask, 0)
#define alloc_page()			_alloc_page(GFP_KERNEL)

/**
 * page_to_virt	-	Get the virtual address of this page
 * @x: the page in question
 * RETURN: the kernel virtual address
 */
#define page_to_virt(x)			__va(PFN_PHYS(page_to_pfn(x)))

static inline unsigned long
__get_free_pages(gfp_t gfp_mask, unsigned int order)
{
	struct page *page;

	page = alloc_pages(gfp_mask, order);
	if (unlikely(!page))
		return 0;
	return (unsigned long)page_to_virt(page);
}

static inline unsigned long
get_zeroed_page(gfp_t gfp_mask)
{
	return __get_free_pages(gfp_mask | __GFP_ZERO, 0);
}

#define __get_free_page(gfp_mask)	__get_free_pages((gfp_mask), 0)

/*
 * virt_to_page(kaddr) returns a valid pointer if and only if
 * virt_addr_valid(kaddr) returns true.
 */
#define virt_to_pfn(kaddr)	(__pa(kaddr) >> PAGE_SHIFT)
#define virt_to_page(addr)	pfn_to_page(virt_to_pfn(addr))
#define pfn_to_kaddr(pfn)	__va((pfn) << PAGE_SHIFT)

#define pfn_to_virt(pfn)	__va((pfn) << PAGE_SHIFT)
#define page_to_phys(page)	(page_to_pfn(page) << PAGE_SHIFT)
#define page_address(page)	__va(PFN_PHYS(page_to_pfn(page)))

static inline bool virt_addr_valid(unsigned long x)
{
	unsigned long y = x - __START_KERNEL_map;

	/* use the carry flag to determine if x was < __START_KERNEL_map */
	if (unlikely(x > y)) {
		x = y + phys_base;

		if (y >= KERNEL_IMAGE_SIZE)
			return false;
	} else {
		x = y + (__START_KERNEL_map - PAGE_OFFSET);

		/* carry flag will be set if starting x was >= PAGE_OFFSET */
		if (x > y)
			return false;
	}

	return pfn_valid(x >> PAGE_SHIFT);
}

static inline int phys_addr_valid(resource_size_t addr)
{
	return !(addr >> default_cpu_info.x86_phys_bits);
}

int __pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address);
int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address);

int __pte_alloc(struct mm_struct *mm, pmd_t *pmd, unsigned long address);
int __pte_alloc_kernel(pmd_t *pmd, unsigned long address);

static inline pud_t *
pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
	return (unlikely(pgd_none(*pgd)) && __pud_alloc(mm, pgd, address))?
		NULL : pud_offset(pgd, address);
}

static inline pmd_t *
pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
	return (unlikely(pud_none(*pud)) && __pmd_alloc(mm, pud, address))?
		NULL : pmd_offset(pud, address);
}

static inline pte_t *
pte_alloc(struct mm_struct *mm, pmd_t *pmd, unsigned long address)
{
	return (unlikely(pmd_none(*pmd) && __pte_alloc(mm, pmd, address))?
		NULL : pte_offset(pmd, address));
}

static inline pte_t *
pte_alloc_kernel(pmd_t *pmd, unsigned long address)
{
	return (unlikely(pmd_none(*pmd)) && __pte_alloc_kernel(pmd, address))?
		NULL : pte_offset(pmd, address);
}

/*
 * Per PTE page lock
 * pmd_page() returns the page that is used as the PTE page
 */
#if USE_SPLIT_PTE_PTLOCKS
static inline spinlock_t *ptlock_ptr(struct page *page)
{
	return &page->ptl;
}

static inline spinlock_t *pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return ptlock_ptr(pmd_page(*pmd));
}

static inline bool ptlock_init(struct page *page)
{
	spin_lock_init(ptlock_ptr(page));
	return true;
}

static inline void pte_lock_deinit(struct page *page)
{
}

#else	/* !USE_SPLIT_PTE_PTLOCKS */
/*
 * We use mm->page_table_lock to guard all pagetable pages of the mm.
 */
static inline spinlock_t *pte_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return &mm->page_table_lock;
}
static inline bool ptlock_init(struct page *page) { return true; }
static inline void pte_lock_deinit(struct page *page) {}
#endif /* USE_SPLIT_PTE_PTLOCKS */

/*
 * Per PMD page lock
 * pmd_to_page returns the page that is used as the PMD page
 */
#if USE_SPLIT_PMD_PTLOCKS
static inline struct page *pmd_to_page(pmd_t *pmd)
{
	unsigned long mask = ~(PTRS_PER_PMD * sizeof(pmd_t) - 1);
	return virt_to_page((void *)((unsigned long) pmd & mask));
}

static inline spinlock_t *pmd_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return ptlock_ptr(pmd_to_page(pmd));
}

static inline bool pgtable_pmd_page_ctor(struct page *page)
{
	return ptlock_init(page);
}

static inline void pgtable_pmd_page_dtor(struct page *page)
{
}

#else /* !USE_SPLIT_PMD_PTLOCKS */
/*
 * We use mm->page_table_lock to guard all pagetable pages of the mm.
 */
static inline spinlock_t *pmd_lockptr(struct mm_struct *mm, pmd_t *pmd)
{
	return &mm->page_table_lock;
}
static inline bool pgtable_pmd_page_ctor(struct page *page) { return true; }
static inline void pgtable_pmd_page_dtor(struct page *page) {}
#endif

static inline spinlock_t *pmd_lock(struct mm_struct *mm, pmd_t *pmd)
{
	spinlock_t *ptl = pmd_lockptr(mm, pmd);
	spin_lock(ptl);
	return ptl;
}

#define pte_offset_lock(mm, pmd, address, ptlp)		\
({							\
	spinlock_t *__ptl = pte_lockptr(mm, pmd);	\
	pte_t *__pte = pte_offset(pmd, address);	\
	*(ptlp) = __ptl;				\
	spin_lock(__ptl);				\
	__pte;						\
})

#define pte_unlock(pte, ptl)				\
do {							\
	spin_unlock(ptl);				\
} while (0)

#define nth_page(page,n)	pfn_to_page(page_to_pfn((page)) + (n))

#define PAGE_ALIGNED(addr)      IS_ALIGNED((unsigned long)addr, PAGE_SIZE)

/* Page Fault flags */
#define FAULT_FLAG_WRITE	0x01	/* Fault was a write access */
#define FAULT_FLAG_MKWRITE	0x02	/* Fault was mkwrite of existing pte */
#define FAULT_FLAG_ALLOW_RETRY	0x04	/* Retry fault if blocking */
#define FAULT_FLAG_RETRY_NOWAIT	0x08	/* Don't drop mmap_sem and wait when retrying */
#define FAULT_FLAG_KILLABLE	0x10	/* The fault task is in SIGKILL killable region */
#define FAULT_FLAG_TRIED	0x20	/* Second try */
#define FAULT_FLAG_USER		0x40	/* The fault originated in userspace */
#define FAULT_FLAG_REMOTE	0x80	/* faulting for non current tsk/mm */
#define FAULT_FLAG_INSTRUCTION  0x100	/* The fault was during an instruction fetch */

void switch_mm_irqs_off(struct mm_struct *prev, struct mm_struct *next,
			struct task_struct *tsk);
void switch_mm(struct mm_struct *prev, struct mm_struct *next,
	       struct task_struct *tsk);

static inline void activate_mm(struct mm_struct *prev, struct mm_struct *next)
{
	switch_mm(prev, next, NULL);
}

#define deactivate_mm(tsk, mm)	\
do {				\
	load_gs_index(0);	\
	loadsegment(fs, 0);	\
} while (0)

struct mm_struct *mm_alloc(void);

/* Remove the current tasks stale references to the old mm_struct */
void mm_release(struct task_struct *, struct mm_struct *);

/* mmput gets rid of the mappings and all user-space */
void mmput(struct mm_struct *);

/* mmdrop drops the mm and the page tables */
void __mmdrop(struct mm_struct *);
static inline void mmdrop(struct mm_struct *mm)
{
	if (unlikely(atomic_dec_and_test(&mm->mm_count)))
		__mmdrop(mm);
}

/* Grab a reference to a task's mm, if it is not already going away */
struct mm_struct *get_task_mm(struct task_struct *task);

#endif /* _LEGO_MM_H_ */
