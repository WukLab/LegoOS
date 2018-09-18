/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MEMORY_MM_H_
#define _LEGO_MEMORY_MM_H_

#include <lego/kernel.h>
#include <lego/rbtree.h>
#include <lego/rwsem.h>
#include <lego/auxvec.h>
#include <lego/spinlock.h>
#include <lego/hashtable.h>

#include <asm/pgtable.h>

#include <memory/elf.h>

struct lego_task_struct;
struct lego_mm_struct;
struct lego_file;
struct vm_area_struct;
struct vm_fault;

/*
 * These are the virtual MM functions - opening of an area, closing and
 * unmapping it (needed to keep files on disk up-to-date etc), pointer
 * to the functions called when a no-page or a wp-page exception occurs.
 */
struct vm_operations_struct {
	void (*open)(struct vm_area_struct * area);
	void (*close)(struct vm_area_struct * area);
	int (*fault)(struct vm_area_struct *, struct vm_fault *);
};

/*
 * This struct defines a memory VMM memory area. There is one of these
 * per VM-area/task.  A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
struct vm_area_struct {
	/* The first cache line has the info for VMA tree walking. */

	unsigned long vm_start;		/* Our start address within vm_mm. */
	unsigned long vm_end;		/* The first byte after our end address */

	/* linked list of VM areas per task, sorted by address */
	struct vm_area_struct *vm_next, *vm_prev;

	struct rb_node vm_rb;

	/*
	 * Largest free memory gap in bytes to the left of this VMA.
	 * Either between this VMA and vma->vm_prev, or between one of the
	 * VMAs below us in the VMA rbtree and its ->vm_prev. This helps
	 * get_unmapped_area find a free area of the right size.
	 */
	unsigned long rb_subtree_gap;

	/* Second cache line starts here. */

	struct lego_mm_struct *vm_mm;	/* The app address space we belong to. */
	pgprot_t vm_page_prot;		/* Access permissions of this VMA. */
	unsigned long vm_flags;		/* Flags, see mm.h. */

	/* Function pointers to deal with this struct. */
	const struct vm_operations_struct *vm_ops;

	/* Information about our backing store: */
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units */
	struct lego_file *vm_file;	/* File we map to (can be NULL )*/
};

/* the node id is acquired by array index, so node id field is not necessary */
struct distvm_node {
	unsigned int count;		/* # of range assigned */
	struct list_head list;		/* list of rangeinfo */
};

struct vma_tree {
	struct rb_root vm_rb;
	struct vm_area_struct *mmap;
	unsigned long begin;		/* vm range limit start */
	unsigned long end;		/* vm range limit end */
	unsigned long highest_vm_end;	/* same as vma struct */
	unsigned long flag;		/* FIXED or not, this field is to
					   help vmrange allocation to identify
					   potential grow of MAP_FIXED request
					   like brk */
	/* fields below mainly serves lego_mm_struct.node_map */
	unsigned long max_gap;		/* max gap of corresponding range */
	int mnode;
	struct list_head list;
};

struct lego_mm_struct {
	struct vm_area_struct *mmap;
	struct rb_root mm_rb;
	unsigned long highest_vm_end;

	unsigned long (*get_unmapped_area)(struct lego_task_struct *p,
				struct lego_file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);
	unsigned long mmap_base;	/* base of mmap area */
	unsigned long mmap_legacy_base;	/* base of mmap area in bottom-up allocations */
	unsigned long task_size;	/* size of task vm space */

	spinlock_t lego_page_table_lock;/* Protects page tables and some counters */
	pgd_t *pgd;			/* root page table */
	atomic_t mm_users;		/* How many users with user space? */
	atomic_t mm_count;		/* How many references to "struct mm_struct" (users count as 1) */
	atomic_long_t nr_ptes;			/* PTE page table pages */
	int map_count;
	unsigned long total_vm;		/* Total pages mapped */
	unsigned long data_vm;		/* VM_WRITE & ~VM_SHARED & ~VM_STACK */
	unsigned long exec_vm;		/* VM_EXEC & ~VM_WRITE & ~VM_STACK */
	unsigned long stack_vm;		/* VM_STACK */
	unsigned long def_flags;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long start_brk, brk, start_stack;
	unsigned long start_bss;
	unsigned long arg_start, arg_end, env_start, env_end;

	/*
	 * This is showed in /proc/PID/auxv
	 * And Lego can not omit this info during elf loading
	 * Actually the GLIBC rely on this shit!
	 */
	unsigned long saved_auxv[AT_VECTOR_SIZE];

	struct rw_semaphore mmap_sem;
	struct lego_task_struct *task;

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	/*
	 * distributed vma range limit management array. Unlike processor side, size of 
	 * each entry is a pointer size. These structures share the semaphore above.
	 */
	struct vma_tree ** vmrange_map;	/* array of pointers or memory 
					 * node ids to vma tree roots 
					 * corresponding to same field in 
					 * mm_struct */
	struct distvm_node ** node_map;	/* array of pointers to memory node involved
					 * in distributed vma */
	struct rb_root vmpool_rb;	/* vm free pool rb tree, used for find free vm
					   range */
	/* 
	 * A pointer point to buffer from handle request, set the pointer at the beginning 
	 * of any vma relevant request (including do_execve) and perform subsequent 
	 * operation, this pointer helps keeping existing API. A good practice is setting
	 * it back to NULL before request handler return.
	 */
	struct vmr_map_reply * reply;	

#ifdef CONFIG_VMA_CACHE_AWARENESS
	unsigned long addr_offset;	/* used for ruducing cache conflict */
#endif

#endif /* CONFIG_DISTRIBUTED_VMA_MEMORY */
};

static inline unsigned long lego_pte_to_virt(pte_t pte)
{
	return pte_val(pte) & PTE_VFN_MASK;
}

#endif /* _LEGO_MEMORY_MM_H_ */
