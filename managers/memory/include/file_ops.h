/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MEMORY_FILE_OPS_H_
#define _LEGO_MEMORY_FILE_OPS_H_

#include <lego/comp_memory.h>

struct file_operations {
	ssize_t (*read)(struct lego_task_struct *, struct lego_file *,
			char __user *, size_t, loff_t *);
	ssize_t (*write)(struct lego_task_struct *, struct lego_file *,
			 const char __user *, size_t, loff_t *);
};

extern struct file_operations ramfs_file_ops;

/* Storage APIs */
ssize_t file_read(struct lego_task_struct *tsk, struct lego_file *file,
		  char __user *buf, size_t count, loff_t *pos);
ssize_t file_write(struct lego_task_struct *tsk, struct lego_file *file,
		   const char __user *buf, size_t count, loff_t *pos);

#endif /* _LEGO_MEMORY_FILE_OPS_H_ */
