/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_COMP_MEMORY_H_
#define _LEGO_COMP_MEMORY_H_

#include <lego/mm.h>
#include <lego/sched.h>
#include <lego/rwsem.h>
#include <lego/spinlock.h>
#include <lego/signal.h>
#include <generated/unistd_64.h>
#include <lego/comp_common.h>	/* must come at last */

#ifdef CONFIG_COMP_MEMORY
void __init memory_component_init(void);
#else
static inline void memory_component_init(void) { }
#endif

struct lego_task_struct;
struct lego_mm_struct;
struct lego_file;
struct vm_fault;

struct anon_vma {
	int unused;
};

/*
 * These are the virtual MM functions - opening of an area, closing and
 * unmapping it (needed to keep files on disk up-to-date etc), pointer
 * to the functions called when a no-page or a wp-page exception occurs.
 */
struct vm_operations_struct {
	void (*open)(struct vm_area_struct * area);
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

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	struct list_head anon_vma_chain;/* Serialized by mmap_sem &
					 * page_table_lock */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	const struct vm_operations_struct *vm_ops;

	/* Information about our backing store: */
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units */
	struct lego_file *vm_file;	/* File we map to (can be NULL )*/
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

	spinlock_t page_table_lock;	/* Protects page tables and some counters */
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
	unsigned long arg_start, arg_end, env_start, env_end;

	struct rw_semaphore mmap_sem;
	struct lego_task_struct *task;
};

struct lego_task_struct {
	unsigned long gpid;

        struct hlist_node link;

	struct list_head tasks;		/* list of all tasks */
	struct lego_mm_struct *mm;

	unsigned int node;
	unsigned int pid;
	unsigned int tgid;

	int exit_signal;
	/*
	 * pointers to (original) parent process, youngest child,
	 * younger sibling, older sibling, respectively.
	 * (p->father can be replaced with p->real_parent->pid)
	 */
	struct lego_task_struct *real_parent; /* real parent process */
	struct lego_task_struct *parent; /* recipient of SIGCHLD, wait4() reports */
	/*
	 * children/sibling forms the list of my natural children
	 */
	struct list_head children;	/* list of my children */
	struct list_head sibling;	/* linkage in my parent's children list */
	struct lego_task_struct *group_leader; /* threadgroup leader */

	struct list_head thread_group;

	char comm[LEGO_TASK_COMM_LEN];	/* executable name excluding path
					 * - access with [gs]et_task_comm (which lock
					 *   it with task_lock())
					 * - initialized normally by setup_new_exec
					 */
	spinlock_t task_lock;
};

static inline bool thread_group_leader(struct lego_task_struct *p)
{
	return p->exit_signal >= 0;
}

static inline void lego_task_lock(struct lego_task_struct *p)
{
	spin_lock(&p->task_lock);
}

static inline void lego_task_unlock(struct lego_task_struct *p)
{
	spin_unlock(&p->task_lock);
}

static inline void lego_set_task_comm(struct lego_task_struct *tsk,
				      const char *buf)
{
	lego_task_lock(tsk);
	strlcpy(tsk->comm, buf, sizeof(tsk->comm));
	lego_task_unlock(tsk);
}

struct file_operations {
	ssize_t (*read)(struct lego_task_struct *, struct lego_file *,
			char __user *, size_t, loff_t *);
	ssize_t (*write)(struct lego_task_struct *, struct lego_file *,
			 const char __user *, size_t, loff_t *);

	int (*mmap)(struct lego_task_struct *, struct lego_file *, struct vm_area_struct *);
};

#define MAX_FILENAME_LEN 128
struct lego_file {
	char filename[MAX_FILENAME_LEN];
	struct file_operations *f_op;
	struct lego_task_struct *task;
};

/* Functions related to the page mapping walk */
//pte_t *page_mapping_walk(struct lego_mm_struct *, unsigned long);

//int page_mapping_update(struct lego_mm_struct *, struct page *);

#endif /* _LEGO_COMP_MEMORY_H_ */
