/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MM_TYPES_H
#define _LEGO_MM_TYPES_H

#include <asm/pgtable.h>

#include <lego/rwsem.h>
#include <lego/types.h>
#include <lego/rbtree.h>
#include <lego/cpumask.h>
#include <lego/spinlock.h>
#include <lego/distvm.h>
/*
 * Options to control if use per-pte, per-pmd locks.
 * The spinlock is embedded within 'struct page'.
 * No dynamic allocation is used now.
 */
#ifdef CONFIG_COMP_PROCESSOR
# define USE_SPLIT_PTE_PTLOCKS	(NR_CPUS >= CONFIG_PROCESSOR_SPLIT_PTLOCK_CPUS)
# define USE_SPLIT_PMD_PTLOCKS	(USE_SPLIT_PTE_PTLOCKS && \
				IS_ENABLED(CONFIG_PROCESSOR_ENABLE_SPLIT_PMD_PTLOCK))
#else
/*
 * Memory component should always use this option
 */
# define USE_SPLIT_PTE_PTLOCKS	1
# define USE_SPLIT_PMD_PTLOCKS	1
#endif

/*
 * Each physical page in the system has a struct page associated with
 * it to keep track of whatever it is we are using the page for at the
 * moment. Note that we have no way to track which tasks are using
 * a page, though if it is a pagecache page, rmap structures can tell us
 * who is mapping it.
 *
 * The objects in struct page are organized in double word blocks in
 * order to allows us to use atomic double word operations on portions
 * of struct page. That is currently only used by slub but the arrangement
 * allows the use of atomic double word operations on the flags/mapping
 * and lru list pointers also.
 */

struct page {
	unsigned long flags;		/* Atomic flags, some possibly
					 * updated asynchronously */

	union {
		pgoff_t index;		/* Our offset within mapping.
					 * Point to mm_struct if pgd page
					 * Point to pcp chunk if used by pcp
					 */
		void *freelist;		/* slab first free object */
	};

	int units;			/* SLOB */

	atomic_t _mapcount;
	atomic_t _refcount;

	struct list_head lru;
	unsigned long private;

#if USE_SPLIT_PTE_PTLOCKS
	spinlock_t ptl;
#endif
} ____cacheline_aligned;

enum {
	MM_FILEPAGES,	/* Resident file mapping pages */
	MM_ANONPAGES,	/* Resident anonymous pages */
	MM_SWAPENTS,	/* Anonymous swap entries */
	MM_SHMEMPAGES,	/* Resident shared memory pages */
	NR_MM_COUNTERS
};

struct mm_struct {
	unsigned long task_size;		/* size of task vm space */
	unsigned long highest_vm_end;		/* highest vma end address */

	atomic_t mm_users;
	atomic_t mm_count;

	pgd_t * pgd;
	int map_count;				/* number of VMAs */

	struct rw_semaphore mmap_sem;
	spinlock_t page_table_lock;		/* Protects page tables and some counters */
	struct list_head mmlist;		/* list of all mm_structs */

	unsigned long total_vm;			/* Total pages mapped */
	unsigned long pinned_vm;		/* Refcount permanently increased */
	unsigned long data_vm;			/* VM_WRITE & ~VM_SHARED & ~VM_STACK */
	unsigned long exec_vm;			/* VM_EXEC & ~VM_WRITE & ~VM_STACK */
	unsigned long stack_vm;			/* VM_STACK */
	unsigned long def_flags;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long start_brk, brk, start_stack;
	unsigned long arg_start, arg_end, env_start, env_end;

	unsigned long flags;			/* Must use atomic bitops to access the bits */

	unsigned long mmap_base;                /* base of mmap area */
	unsigned long cached_hole_size;         /* if non-zero, the largest hole below free_area_cache */
	unsigned long free_area_cache;          /* first hole of size cached_hole_size or larger */

	struct vm_area_struct * mmap_cache;     /* last find_vma result */
	struct rb_root mm_rb;

#ifdef CONFIG_DISTRIBUTED_VMA_PROCESSOR
	vmr16 *vmrange_map;			/* allocation of vm ranges on each node 
						 * corresponding to same name in
						 * lego_mm_struct */
	spinlock_t vmr_lock;			/* protect vma_roots array */
#endif /* CONFIG_DISTRIBUTED_VMA_PROCESSOR */ 

	int gpid;
	struct list_head list;

	cpumask_var_t cpu_vm_mask_var;		/* CPUs this VM has run on */
};

static inline void mm_init_cpumask(struct mm_struct *mm)
{
	cpumask_clear(mm->cpu_vm_mask_var);
}

/* Future-safe accessor for struct mm_struct's cpu_vm_mask. */
static inline cpumask_t *mm_cpumask(struct mm_struct *mm)
{
	return mm->cpu_vm_mask_var;
}

#endif /* _LEGO_MM_TYPES_H */
