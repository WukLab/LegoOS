/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/kernel.h>
#include <memory/include/file_ops.h>

extern char __ramfs_start[], __ramfs_end[];

ssize_t ramfs_read(struct lego_task_struct *tsk, struct lego_file *file,
		   char *buf, size_t count, loff_t *pos)
{
	char *start;

	start = __ramfs_start + *pos;
	memcpy(buf, start, count);
	*pos += count;

	pr_info("%p -> %p, cnt: %zu\n", start, buf, count);
	return 0;
}

ssize_t ramfs_write(struct lego_task_struct *tsk, struct lego_file *file,
		    const char *buf, size_t count, loff_t *pos)
{
	return -EINVAL;
}

struct file_operations ramfs_file_ops = {
	.read	= ramfs_read,
	.write	= ramfs_write,
};
