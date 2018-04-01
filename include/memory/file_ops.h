/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MEMORY_FILE_OPS_H_
#define _LEGO_MEMORY_FILE_OPS_H_

#include <memory/task.h>
#include <memory/file_types.h>

extern struct lego_file_operations ramfs_file_ops;
extern struct lego_file_operations storage_file_ops;

/* Storage APIs */
ssize_t file_read(struct lego_task_struct *tsk, struct lego_file *file,
		  char __user *buf, size_t count, loff_t *pos);
ssize_t file_write(struct lego_task_struct *tsk, struct lego_file *file,
		   const char __user *buf, size_t count, loff_t *pos);
ssize_t kernel_read(struct lego_task_struct *tsk, struct lego_file *file,
		loff_t offset, char *addr, unsigned long count);

struct lego_file *file_open(struct lego_task_struct *tsk, const char *filename);
void file_close(struct lego_file *file);

ssize_t storage_read(struct lego_task_struct *tsk,
			    struct lego_file *file,
			    char *buf, size_t count, loff_t *pos);

ssize_t __storage_read(struct lego_task_struct *tsk, char *f_name,
		       char __user *buf, size_t count, loff_t *pos);

ssize_t __storage_write(struct lego_task_struct *tsk, char *f_name,
			const char *buf, size_t count, loff_t *pos);

#endif /* _LEGO_MEMORY_FILE_OPS_H_ */
