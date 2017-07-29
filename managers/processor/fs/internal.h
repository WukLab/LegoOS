/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _PROCESSOR_FS_INTERNAL_H_
#define _PROCESSOR_FS_INTERNAL_H_

#include <lego/bug.h>
#include <lego/files.h>
#include <lego/atomic.h>

static inline void get_file(struct file *filp)
{
	atomic_inc(&filp->f_count);
}

static void __put_file(struct file *filp)
{
	BUG_ON(atomic_read(&filp->f_count) != 0);
	kfree(filp);
}

static inline void put_file(struct file *filp)
{
	if (atomic_dec_and_test(&filp->f_count))
		__put_file(filp);
}

struct file *fdget(int fd);

#endif /* _PROCESSOR_FS_INTERNAL_H_ */
