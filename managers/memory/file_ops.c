/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/slab.h>
#include <lego/kernel.h>
#include <lego/spinlock.h>
#include <lego/comp_memory.h>

#include <memory/file_ops.h>

ssize_t file_read(struct lego_task_struct *tsk, struct lego_file *file,
		  char __user *buf, size_t count, loff_t *pos)
{
	return file->f_op->read(tsk, file, buf, count, pos);
}

ssize_t kernel_read(struct lego_task_struct *tsk, struct lego_file *file,
		loff_t offset, char *addr, unsigned long count)
{
	loff_t pos = offset;

	return file_read(tsk, file, (void __user *)addr, count, &pos);
}

ssize_t file_write(struct lego_task_struct *tsk, struct lego_file *file,
		   const char __user *buf, size_t count, loff_t *pos)
{
	return file->f_op->write(tsk, file, buf, count, pos);
}

/*
 * Open a file, allocate and initialized the lego_file data structure
 */
struct lego_file *file_open(struct lego_task_struct *tsk, const char *filename)
{
	struct lego_file *file;

	file = kzalloc(sizeof(*file), GFP_KERNEL);
	if (!file)
		return ERR_PTR(-ENOMEM);

	atomic_set(&file->f_count, 1);
	strncpy(file->filename, filename, MAX_FILENAME_LEN);

#ifdef CONFIG_USE_RAMFS
	file->f_op = &ramfs_file_ops;
#else
	file->f_op = &storage_file_ops;
#endif

	return file;
}

void file_close(struct lego_file *file)
{
	BUG_ON(!file);
	put_lego_file(file);
}

void __put_lego_file(struct lego_file *filp)
{
	BUG_ON(atomic_read(&filp->f_count) != 0);

	pr_debug("%s: fname: %s\n", __func__, filp->filename);
	kfree(filp);
}
