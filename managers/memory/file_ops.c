/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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

#include <memory/include/file_ops.h>

ssize_t file_read(struct lego_task_struct *tsk, struct lego_file *file,
		  char __user *buf, size_t count, loff_t *pos)
{
	return ramfs_file_ops.read(tsk, file, buf, count, pos);
}

ssize_t file_write(struct lego_task_struct *tsk, struct lego_file *file,
		   const char __user *buf, size_t count, loff_t *pos)
{
	return ramfs_file_ops.write(tsk, file, buf, count, pos);
}

/*
 * Open a file, allocate and initialized the lego_file data structure
 */
struct lego_file *file_open(struct lego_task_struct *tsk, const char *filename)
{
	struct lego_file *file;

	file = kmalloc(sizeof(*file), GFP_KERNEL);
	if (!file)
		return ERR_PTR(-ENOMEM);

	strncpy(file->filename, filename, MAX_FILENAME_LEN);
	file->f_op = &ramfs_file_ops;
	file->task = tsk;

	return file;
}

void file_close(struct lego_file *file)
{
	BUG_ON(!file);
	kfree(file);
}
