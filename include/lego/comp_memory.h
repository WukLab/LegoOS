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
#include <lego/spinlock.h>

/*
 * mmap flags
 */
#define PROT_READ	0x01		/* page can be read */
#define PROT_WRITE	0x02		/* page can be written */
#define PROT_EXEC	0x04		/* page can be executed */
#define PROT_SEM	0x08		/* page may be used for atomic ops */
#define PROT_NONE	0x00		/* page can not be accessed */

#define MAP_SHARED	0x01		/* Share changes */
#define MAP_PRIVATE	0x02		/* Changes are private */
#define MAP_TYPE	0x0f		/* Mask for type of mapping */
#define MAP_FIXED	0x10		/* Interpret addr exactly */
#define MAP_ANONYMOUS	0x20		/* don't use a file */
#define MAP_GROWSDOWN	0x0100		/* stack-like segment */
#define MAP_DENYWRITE	0x0800		/* ETXTBSY */
#define MAP_EXECUTABLE	0x1000		/* mark it as an executable */
#define MAP_LOCKED	0x2000		/* pages are locked */

/*
 * vm_flags in vm_area_struct
 */
#define VM_NONE		0x00000000
#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

#define VM_GROWSUP	VM_NONE
#define VM_GROWSDOWN	0x00000100	/* general info on the segment */
#define VM_UFFD_MISSING	0x00000200	/* missing pages tracking */
#define VM_PFNMAP	0x00000400	/* Page-ranges managed without "struct page", just pure PFN */
#define VM_DENYWRITE	0x00000800	/* ETXTBSY on write attempts.. */

#define VM_LOCKED	0x00002000
#define VM_IO           0x00004000	/* Memory mapped I/O or similar */
#define VM_SEQ_READ	0x00008000	/* App will access data sequentially */
#define VM_RAND_READ	0x00010000	/* App will not benefit from clustered reads */

/*
 * Special vmas that are non-mergable, non-mlock()able.
 */
#define VM_SPECIAL		(VM_IO | VM_PFNMAP)

#define VM_DATA_DEFAULT_FLAGS	(VM_READ | VM_WRITE) 

#define VM_STACK		VM_GROWSDOWN
#define VM_STACK_DEFAULT_FLAGS	VM_DATA_DEFAULT_FLAGS
#define VM_STACK_FLAGS		(VM_STACK | VM_STACK_DEFAULT_FLAGS)

/* Bits set in the VMA until the stack is in its final location */
#define VM_STACK_INCOMPLETE_SETUP	(VM_RAND_READ | VM_SEQ_READ)

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

/*
 * This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define TASK_UNMAPPED_BASE	(PAGE_ALIGN(TASK_SIZE / 3))

struct lego_task_struct;
struct lego_mm_struct;
struct lego_file;

struct anon_vma {
	int unused;
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

	pgd_t *pgd;
	atomic_t mm_users;		/* How many users with user space? */
	atomic_t mm_count;		/* How many references to "struct mm_struct" (users count as 1) */
	int map_count;
	unsigned long total_vm;		/* Total pages mapped */
	unsigned long data_vm;		/* VM_WRITE & ~VM_SHARED & ~VM_STACK */
	unsigned long exec_vm;		/* VM_EXEC & ~VM_WRITE & ~VM_STACK */
	unsigned long stack_vm;		/* VM_STACK */
	unsigned long def_flags;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long start_brk, brk, start_stack;
	unsigned long arg_start, arg_end, env_start, env_end;

	struct lego_task_struct *task;
};

struct lego_task_struct {
	unsigned long node;
	unsigned long pid;
	unsigned long gpid;

	unsigned char comm[TASK_COMM_LEN];
	spinlock_t task_lock;
	struct lego_mm_struct *mm;
};

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

#define MAX_FILENAME_LEN 128
struct lego_file {
	const char filename[MAX_FILENAME_LEN];
};

#ifdef CONFIG_COMP_MEMORY
void __init memory_component_init(void);
#else
static inline void memory_component_init(void) { }
#endif

/* Is the vma a continuation of the stack vma above it? */
static inline int vma_growsdown(struct vm_area_struct *vma, unsigned long addr)
{
	return vma && (vma->vm_end == addr) && (vma->vm_flags & VM_GROWSDOWN);
}

static inline bool vma_is_anonymous(struct vm_area_struct *vma)
{
	return true;
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

/* arch-hook for loader */
void arch_pick_mmap_layout(struct lego_mm_struct *mm);

int insert_vm_struct(struct lego_mm_struct *, struct vm_area_struct *);

/* Look up the first VMA which satisfies  addr < vm_end,  NULL if none. */
struct vm_area_struct *find_vma(struct lego_mm_struct *mm, unsigned long addr);

int vm_munmap(struct lego_task_struct *p, unsigned long start, size_t len);
unsigned long vm_mmap(struct lego_task_struct *p, struct lego_file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long offset);

unsigned long vm_mmap_pgoff(struct lego_task_struct *p, struct lego_file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long pgoff);

int vm_brk(struct lego_task_struct *tsk,
	   unsigned long start, unsigned long len);

struct lego_mm_struct *lego_mm_alloc(struct lego_task_struct *p);

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
void lego_mm_release(struct lego_task_struct *tsk, struct lego_mm_struct *mm);

/* Storage APIs */
ssize_t file_read(struct lego_task_struct *tsk, struct lego_file *file,
		  char __user *buf, size_t count, loff_t *pos);
ssize_t file_write(struct lego_task_struct *tsk, struct lego_file *file,
		   const char __user *buf, size_t count, loff_t *pos);

#endif /* _LEGO_COMP_MEMORY_H_ */
