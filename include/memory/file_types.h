/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MEMORY_FILE_TYPES_H_
#define _LEGO_MEMORY_FILE_TYPES_H_

#include <lego/atomic.h>
#include <lego/kernel.h>
#include <memory/task.h>

struct lego_file;

struct lego_file_operations {
	ssize_t (*read)(struct lego_task_struct *, struct lego_file *,
			char __user *, size_t, loff_t *);
	ssize_t (*write)(struct lego_task_struct *, struct lego_file *,
			 const char __user *, size_t, loff_t *);

	int (*mmap)(struct lego_task_struct *, struct lego_file *, struct vm_area_struct *);
};

#define MAX_FILENAME_LEN 	MAX_FILENAME_LENGTH
struct lego_file {
	atomic_t			f_count;
	char				filename[MAX_FILENAME_LEN];
	struct lego_file_operations	*f_op;
};

static inline void get_lego_file(struct lego_file *filp)
{
	atomic_inc(&filp->f_count);
}

void __put_lego_file(struct lego_file *filp);

static inline void put_lego_file(struct lego_file *filp)
{
	if (atomic_dec_and_test(&filp->f_count))
		__put_lego_file(filp);
}

#endif /* _LEGO_MEMORY_FILE_TYPES_H_ */
