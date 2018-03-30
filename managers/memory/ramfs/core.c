/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/kernel.h>
#include <lego/comp_memory.h>
#include <lego/comp_storage.h>
#include <lego/fit_ibapi.h>

#include <memory/vm.h>
#include <memory/file_ops.h>

extern char __ramfs_start[], __ramfs_end[];

static ssize_t ramfs_read(struct lego_task_struct *tsk, struct lego_file *file,
			  char *buf, size_t count, loff_t *pos)
{
	char *start;

	start = __ramfs_start + *pos;
	memcpy(buf, start, count);
	*pos += count;

	return count;
}

static ssize_t ramfs_write(struct lego_task_struct *tsk, struct lego_file *file,
			   const char *buf, size_t count, loff_t *pos)
{
	return -EINVAL;
}

static int ramfs_vma_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct lego_task_struct *tsk;
	struct lego_file *file;
	size_t count;
	loff_t pos;
	unsigned long page;

	page = __get_free_page(GFP_KERNEL);
	if (unlikely(!page))
		return VM_FAULT_OOM;

	tsk = vma->vm_mm->task;
	file = vma->vm_file;
	count = PAGE_SIZE;
	pos = vmf->pgoff << PAGE_SHIFT;

	ramfs_read(tsk, file, (char *)page, count, &pos);

	vmf->page = page;

	return 0;
}

static struct vm_operations_struct ramfs_vma_ops = {
	.fault	= ramfs_vma_fault,
};

static int ramfs_mmap(struct lego_task_struct *tsk, struct lego_file *file,
		      struct vm_area_struct *vma)
{
	vma->vm_ops = &ramfs_vma_ops;
	return 0;
}

struct lego_file_operations ramfs_file_ops = {
	.read	= ramfs_read,
	.write	= ramfs_write,
	.mmap	= ramfs_mmap,
};
