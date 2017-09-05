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

extern struct lego_file_operations ramfs_file_ops;
extern struct lego_file_operations storage_file_ops;

/* Storage APIs */
ssize_t file_read(struct lego_task_struct *tsk, struct lego_file *file,
		  char __user *buf, size_t count, loff_t *pos);
ssize_t file_write(struct lego_task_struct *tsk, struct lego_file *file,
		   const char __user *buf, size_t count, loff_t *pos);

struct lego_file *file_open(struct lego_task_struct *tsk, const char *filename);
void file_close(struct lego_file *file);

#endif /* _LEGO_MEMORY_FILE_OPS_H_ */
