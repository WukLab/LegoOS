/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/rbtree.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/netmacro.h>
#include <lego/comp_memory.h>

struct vm_area_struct *find_vma(struct lego_mm_struct *mm, unsigned long addr)
{
	return NULL;
}

unsigned long unmapped_area(struct lego_task_struct *p,
			    struct vm_unmapped_area_info *info)
{
	return 0;
}

unsigned long unmapped_area_topdown(struct lego_task_struct *p,
				    struct vm_unmapped_area_info *info)
{
	return 0;
}


static unsigned long
get_unmapped_area(struct lego_task_struct *p, struct lego_file *file,
		  unsigned long addr, unsigned long len, unsigned long pgoff,
		  unsigned long flags)
{
	return 0;
}

/* minimum virtual address that a process is allowed to mmap */
static unsigned long sysctl_mmap_min_addr = PAGE_SIZE;

/*
 * If a hint addr is less than mmap_min_addr change hint to be as
 * low as possible but still greater than mmap_min_addr
 */
static inline unsigned long round_hint_to_min(unsigned long hint)
{
	hint &= PAGE_MASK;
	if (((void *)hint != NULL) &&
	    (hint < sysctl_mmap_min_addr))
		return PAGE_ALIGN(sysctl_mmap_min_addr);
	return hint;
}

/*
 * The caller must hold down_write(&current->mm->mmap_sem).
 */
unsigned long do_mmap(struct lego_task_struct *p, struct lego_file *file,
	unsigned long addr, unsigned long len, unsigned long prot,
	unsigned long flags, vm_flags_t vm_flags, unsigned long pgoff)
{
	struct lego_mm_struct *mm = p->mm;

	if (!(flags & MAP_FIXED))
		addr = round_hint_to_min(addr);

	/* Careful about overflows.. */
	len = PAGE_ALIGN(len);
	if (!len)
		return -ENOMEM;

	/* offset overflow? */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
		return -EOVERFLOW;

	/*
	 * Obtain the address to map to. we verify (or select) it and ensure
	 * that it represents a valid section of the address space.
	 */
	addr = get_unmapped_area(p, file, addr, len, pgoff, flags);
	if (unlikely(offset_in_page(addr))) /* which means error */
		return addr;


	return 0;
}

static inline unsigned long
do_mmap_pgoff(struct lego_task_struct *p, struct lego_file *file,
	unsigned long addr, unsigned long len, unsigned long prot,
	unsigned long flags, unsigned long pgoff)
{
	return do_mmap(p, file, addr, len, prot, flags, 0, pgoff);
}

unsigned long vm_mmap_pgoff(struct lego_task_struct *p, struct lego_file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long pgoff)
{
	unsigned long ret;

	/* TODO mm locking */
	ret = do_mmap_pgoff(p, file, addr, len, prot, flag, pgoff);
	return ret;
}

unsigned long vm_mmap(struct lego_task_struct *p, struct lego_file *file,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flag, unsigned long offset)
{
	if (unlikely(offset + PAGE_ALIGN(len) < offset))
		return -EINVAL;
	if (unlikely(offset_in_page(offset)))
		return -EINVAL;

	return vm_mmap_pgoff(p, file, addr, len, prot, flag, offset >> PAGE_SHIFT);
}
