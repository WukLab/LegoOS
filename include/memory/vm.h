/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MEMORY_VM_H_
#define _LEGO_MEMORY_VM_H_

#include <lego/bug.h>
#include <lego/mmap.h>
#include <lego/pgfault.h>

#include <memory/task.h>
#include <memory/vm-pgtable.h>

#include <monitor/common.h>

/*
 * Optimisation macro.  It is equivalent to:
 *      (x & bit1) ? bit2 : 0
 * but this version is faster.
 * ("bit1" and "bit2" must be single bits)
 */
#define _calc_vm_trans(x, bit1, bit2) \
  ((bit1) <= (bit2) ? ((x) & (bit1)) * ((bit2) / (bit1)) \
   : ((x) & (bit1)) / ((bit1) / (bit2)))

/*
 * This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define TASK_UNMAPPED_BASE	(PAGE_ALIGN(TASK_SIZE / 3))

/*
 * Combine the mmap "prot" argument into "vm_flags" used internally.
 */
static inline unsigned long
calc_vm_prot_bits(unsigned long prot)
{
	return _calc_vm_trans(prot, PROT_READ,  VM_READ ) |
	       _calc_vm_trans(prot, PROT_WRITE, VM_WRITE) |
	       _calc_vm_trans(prot, PROT_EXEC,  VM_EXEC);
}

/*
 * Combine the mmap "flags" argument into "vm_flags" used internally.
 */
static inline unsigned long
calc_vm_flag_bits(unsigned long flags)
{
	return _calc_vm_trans(flags, MAP_GROWSDOWN,  VM_GROWSDOWN ) |
	       _calc_vm_trans(flags, MAP_DENYWRITE,  VM_DENYWRITE ) |
	       _calc_vm_trans(flags, MAP_LOCKED,     VM_LOCKED    );
}

/* Is the vma a continuation of the stack vma above it? */
static inline int vma_growsdown(struct vm_area_struct *vma, unsigned long addr)
{
	return vma && (vma->vm_end == addr) && (vma->vm_flags & VM_GROWSDOWN);
}

static inline bool vma_is_anonymous(struct vm_area_struct *vma)
{
	return !vma->vm_ops;
}

/*
 * These three helpers classifies VMAs for virtual memory accounting.
 */

/*
 * Executable code area - executable, not writable, not stack
 */
static inline bool is_exec_mapping(vm_flags_t flags)
{
	return (flags & (VM_EXEC | VM_WRITE | VM_STACK)) == VM_EXEC;
}

/*
 * Stack area - atomatically grows in one direction
 *
 * VM_GROWSUP / VM_GROWSDOWN VMAs are always private anonymous:
 * do_mmap() forbids all other combinations.
 */
static inline bool is_stack_mapping(vm_flags_t flags)
{
	return (flags & VM_STACK) == VM_STACK;
}

/*
 * Data area - private, writable, not stack
 */
static inline bool is_data_mapping(vm_flags_t flags)
{
	return (flags & (VM_WRITE | VM_SHARED | VM_STACK)) == VM_WRITE;
}

struct vm_unmapped_area_info {
#define VM_UNMAPPED_AREA_TOPDOWN 1
	unsigned long flags;
	unsigned long length;
	unsigned long low_limit;
	unsigned long high_limit;
	unsigned long align_mask;
	unsigned long align_offset;
};

unsigned long
unmapped_area(struct lego_task_struct *p, struct vm_unmapped_area_info *info);
unsigned long
unmapped_area_topdown(struct lego_task_struct *p, struct vm_unmapped_area_info *info);

unsigned long
get_unmapped_area(struct lego_task_struct *p, struct lego_file *file,
		  unsigned long addr, unsigned long len, unsigned long pgoff,
		  unsigned long flags);

/*
 * Search for an unmapped address range.
 *
 * We are looking for a range that:
 * - does not intersect with any VMA;
 * - is contained within the [low_limit, high_limit) interval;
 * - is at least the desired size.
 * - satisfies (begin_addr & align_mask) == (align_offset & align_mask)
 */
static inline unsigned long
vm_unmapped_area(struct lego_task_struct *p, struct vm_unmapped_area_info *info)
{
	if (info->flags & VM_UNMAPPED_AREA_TOPDOWN)
		return unmapped_area_topdown(p, info);
	else
		return unmapped_area(p, info);
}

pgprot_t vm_get_page_prot(unsigned long vm_flags);

/* For distributed vma, make some mmap API public */
void vma_gap_update(struct vm_area_struct *vma);
unsigned long do_mmap(struct lego_task_struct *p, struct lego_file *file,
	unsigned long addr, unsigned long len, unsigned long prot,
	unsigned long flags, vm_flags_t vm_flags, unsigned long pgoff);

/* arch-hook for loader */
void arch_pick_mmap_layout(struct lego_mm_struct *mm);

int insert_vm_struct(struct lego_mm_struct *, struct vm_area_struct *);

bool may_expand_vm(struct lego_mm_struct *, vm_flags_t, unsigned long npages);

/* Look up the first VMA which satisfies  addr < vm_end,  NULL if none. */
struct vm_area_struct *find_vma(struct lego_mm_struct *mm, unsigned long addr);

int vm_munmap(struct lego_task_struct *p, unsigned long start, size_t len);
unsigned long vm_mmap(struct lego_task_struct *p, struct lego_file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long offset);

unsigned long vm_mmap_pgoff(struct lego_task_struct *p, struct lego_file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long pgoff);

int do_munmap(struct lego_mm_struct *mm, unsigned long start, size_t len);
int do_brk(struct lego_task_struct *p, unsigned long addr,
	   unsigned long request);

void unmap_vmas(struct vm_area_struct *vma, unsigned long start_addr,
		unsigned long end_addr);

/*
 * Look up the first VMA which intersects the interval start_addr..end_addr-1,
 * NULL if none.  Assume start_addr < end_addr.
 */

static inline struct vm_area_struct *
find_vma_intersection(struct lego_mm_struct * mm,
		      unsigned long start_addr, unsigned long end_addr)
{
	struct vm_area_struct *vma = find_vma(mm, start_addr);

	if (vma && end_addr <= vma->vm_start)
		vma = NULL;
	return vma;
}

int vm_brk(struct lego_task_struct *tsk,
	   unsigned long start, unsigned long len);

void __vma_link_rb(struct lego_mm_struct *mm, struct vm_area_struct *vma,
		struct rb_node **rb_link, struct rb_node *rb_parent);
int __vma_adjust(struct vm_area_struct *vma, unsigned long start,
	unsigned long end, pgoff_t pgoff, struct vm_area_struct *insert,
	struct vm_area_struct *expand);

static inline int vma_adjust(struct vm_area_struct *vma, unsigned long start,
	unsigned long end, pgoff_t pgoff, struct vm_area_struct *insert)
{
	return __vma_adjust(vma, start, end, pgoff, insert, NULL);
}

int vma_expandable(struct lego_task_struct *tsk,
		   struct vm_area_struct *vma, unsigned long delta);
struct vm_area_struct *
vma_to_resize(unsigned long addr, unsigned long old_len,
	      unsigned long new_len, struct lego_task_struct *tsk);
unsigned long move_vma(struct lego_task_struct *tsk, struct vm_area_struct *vma,
		unsigned long old_addr, unsigned long old_len,
		unsigned long new_len, unsigned long new_addr);

struct lego_mm_struct *
lego_mm_init(struct lego_mm_struct *mm, struct lego_task_struct *p);

struct lego_mm_struct *
lego_mm_alloc(struct lego_task_struct *p, struct lego_task_struct *parent);

/* lego_mmdrop drops the mm and the page tables */
void __lego_mmdrop(struct lego_mm_struct *);
static inline void lego_mmdrop(struct lego_mm_struct *mm)
{
	if (unlikely(atomic_dec_and_test(&mm->mm_count)))
		__lego_mmdrop(mm);
}

/* Decrement the use count and release all resources for an mm */
void __lego_mmput(struct lego_mm_struct *);
static inline void lego_mmput(struct lego_mm_struct *mm)
{
	if (unlikely(atomic_dec_and_test(&mm->mm_users)))
		__lego_mmput(mm);
}

static inline unsigned long vma_pages(struct vm_area_struct *vma)
{
	return (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
}

int expand_stack(struct vm_area_struct *vma, unsigned long address);
struct vm_area_struct *find_extend_vma(struct lego_mm_struct *mm, unsigned long addr);
int mprotect_fixup(struct lego_task_struct *tsk, struct vm_area_struct *vma,
		struct vm_area_struct **pprev, unsigned long start,
		unsigned long end, unsigned long newflags);

void exit_lego_mmap(struct lego_mm_struct *mm);


/* fault.c */
/*
 * vm_fault is filled by the the pagefault handler and passed to the vma's
 * ->fault function. The vma's ->fault is responsible for returning a bitmask
 * of VM_FAULT_xxx flags that give details about how the fault was handled.
 *
 * MM layer fills up gfp_mask for page allocations but fault handler might
 * alter it if its implementation requires a different allocation context.
 *
 * pgoff should be used in favour of virtual_address, if possible.
 */
struct vm_fault {
	unsigned int flags;		/* FAULT_FLAG_xxx flags */
	gfp_t gfp_mask;			/* gfp mask to be used for allocations */
	pgoff_t pgoff;			/* Logical page offset based on vma */
	unsigned long __user virtual_address;	/* Faulting virtual address */

	unsigned long page;		/* ->fault handlers should return a
					 * page here (kernel virtual address),
					 * unless VM_FAULT_NOPAGE
					 * is set (which is also implied by
					 * VM_FAULT_ERROR).
					 */
};

int handle_lego_mm_fault(struct vm_area_struct *vma, unsigned long address,
			 unsigned int flags, unsigned long *ret_va, unsigned long *mapping_flags);

int handle_lego_mmap_faults(struct vm_area_struct *vma, unsigned long address,
			unsigned int flags, u32 nr_pages);

int count_empty_entries(struct vm_area_struct *vma, unsigned long address,
	       		u32 nr_pages);
/* pgtable.c */
extern unsigned long lego_move_page_tables(struct vm_area_struct *vma,
		unsigned long old_addr, struct vm_area_struct *new_vma,
		unsigned long new_addr, unsigned long len);

int lego_copy_page_range(struct lego_mm_struct *dst, struct lego_mm_struct *src,
		struct vm_area_struct *vma);

void lego_free_pgd_range(struct lego_mm_struct *mm,
			 unsigned long addr, unsigned long end,
			 unsigned long floor, unsigned long ceiling);

void lego_free_pgtables(struct vm_area_struct *start_vma,
		unsigned long floor, unsigned long ceiling);

void lego_unmap_page_range(struct vm_area_struct *vma,
			   unsigned long addr, unsigned long end);

/* debug.c */
void dump_all_vmas_simple(struct lego_mm_struct *mm);
void dump_vma_simple(const struct vm_area_struct *vma);
void dump_all_vmas(struct lego_mm_struct *mm);
void dump_vma(const struct vm_area_struct *vma);
void dump_lego_mm(const struct lego_mm_struct *mm);
#define VM_BUG_ON_VMA(cond, vma)					\
	do {								\
		if (unlikely(cond)) {					\
			dump_vma(vma);					\
			BUG();						\
		}							\
	} while (0)
#ifndef CONFIG_DEBUG_VMA
#define VM_BUG_ON_MM(cond, mm)						\
	do {								\
		if (unlikely(cond)) {					\
			dump_lego_mm(mm);				\
			BUG();						\
		}							\
	} while (0)

static inline void dump_vmas_onetree(struct vma_tree *root) {}
static inline void dump_vmas_onenode(struct lego_mm_struct *mm) {}
static inline void dump_gaps_onenode(struct lego_mm_struct *mm, unsigned long id) {}
static inline void dump_new_context(struct lego_mm_struct *mm) {}
static inline void dump_vmpool(struct lego_mm_struct *mm) {}
static inline void dump_reply(struct vmr_map_reply *reply) {}
static inline void dump_alloc_schemes(int count, struct alloc_scheme *scheme) {}
static inline void mmap_brk_validate(struct lego_mm_struct *mm, unsigned long addr, 
		       unsigned long len) {}
#else
/* dist_mmap_dump.c */
void dump_vmas_onetree(struct vma_tree *root);
void dump_vmas_onenode(struct lego_mm_struct *mm);
void dump_gaps_onenode(struct lego_mm_struct *mm, unsigned long id);
void dump_new_context(struct lego_mm_struct *mm);
void dump_vmpool(struct lego_mm_struct *mm);
void dump_reply(struct vmr_map_reply *reply);
void dump_alloc_schemes(int count, struct alloc_scheme *scheme);
void mmap_brk_validate(struct lego_mm_struct *mm, unsigned long addr, 
		       unsigned long len);
void mmap_brk_validate_local(struct lego_mm_struct *mm, unsigned long addr,
			     unsigned long len);

#define VM_BUG_ON_MM(cond, mm)						\
	do {								\
		if (unlikely(cond)) {					\
			dump_lego_mm(mm);				\
			dump_vmpool(mm);				\
			dump_vmas_onenode(mm);				\
			dump_gaps_onenode(mm, MY_NODE_ID);		\
			BUG();						\
		}							\
	} while (0)
#endif


/* gup.c */
#define FOLL_WRITE	0x01	/* check pte is writable */
#define FOLL_TOUCH	0x02	/* mark page accessed */
#define FOLL_GET	0x04	/* do get_page on page */
#define FOLL_DUMP	0x08	/* give error on hole if it would be zero */
#define FOLL_FORCE	0x10	/* get_user_pages read/write w/o permission */
#define FOLL_NOWAIT	0x20	/* if a disk transfer is needed, start the IO
				 * and return without waiting upon it */
#define FOLL_POPULATE	0x40	/* fault in page */
#define FOLL_SPLIT	0x80	/* don't return transhuge pages, split them */
#define FOLL_HWPOISON	0x100	/* check page is hwpoisoned */
#define FOLL_NUMA	0x200	/* force NUMA hinting page fault */
#define FOLL_MIGRATION	0x400	/* wait for page to replace migration entry */
#define FOLL_TRIED	0x800	/* a retry, previous pass started an IO */
#define FOLL_MLOCK	0x1000	/* lock present pages */
#define FOLL_REMOTE	0x2000	/* we are working on non-current tsk/mm */
#define FOLL_COW	0x4000	/* internal GUP flag */

int faultin_page(struct vm_area_struct *vma, unsigned long start,
		 unsigned long flags, unsigned long *kvaddr);

unsigned long find_page(struct vm_area_struct *vma, unsigned long address);

long get_user_pages(struct lego_task_struct *tsk, unsigned long start,
		    unsigned long nr_pages, unsigned int gup_flags,
		    unsigned long *pages, struct vm_area_struct **vmas);

int __lego_mm_populate(struct lego_mm_struct *mm, unsigned long start,
		       unsigned long len, int ignore_errors);

long populate_vma_page_range(struct vm_area_struct *vma,
			     unsigned long start, unsigned long end,
			     int *nonblocking);

static inline void
lego_mm_populate(struct lego_mm_struct *mm, unsigned long start, unsigned long len)
{
	/* ignore errors */
	__lego_mm_populate(mm, start, len, 1);
}

/* uaccess.c */
unsigned long _lego_copy_to_user(struct lego_task_struct *tsk,
				 void __user *to, const void *from, size_t n,
				 const char *caller);

unsigned long _lego_copy_from_user(struct lego_task_struct *tsk,
				   void *to , const void __user *from, size_t n,
				   const char *caller);

unsigned long __must_check _lego_clear_user(struct lego_task_struct *tsk,
					    void * __user dst, size_t cnt,
					    const char *caller);

#define lego_copy_to_user(tsk, to, from, n)	\
	_lego_copy_to_user(tsk, to, from, n, __func__)

#define lego_copy_from_user(tsk, to, from, n)	\
	_lego_copy_from_user(tsk, to, from, n, __func__)

#define lego_clear_user(tsk, dst, cnt)	\
	_lego_clear_user(tsk, dst, cnt, __func__)

#endif /* _LEGO_MEMORY_VM_H_ */
