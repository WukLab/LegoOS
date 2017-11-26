/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/stat.h>
#include <lego/slab.h>
#include <lego/uaccess.h>
#include <lego/files.h>
#include <lego/syscalls.h>
#include <lego/spinlock.h>
#include <lego/comp_processor.h>
#include <processor/fs.h>

/*
 * Defined managers/processor/fs/stdio.c
 *
 * By default, Lego opens stdin, stdout, stderr
 * for all user program. If they want to open /dev/tty again,
 * it will use the same ops.
 */
extern const struct file_operations stdio_file_op;

struct dev_file_struct {
	char f_name[FILENAME_LEN_DEFAULT];
	const struct file_operations *f_op;
};

static struct dev_file_struct dev_files[] = {
	{
		.f_name	= "/dev/tty",
		.f_op	= &stdio_file_op,
	},
};

int dev_file_open(struct file *f, char *f_name)
{
	struct dev_file_struct *dev_file;
	int i, ret;

	ret = -EBADF;
	for (i = 0; i < ARRAY_SIZE(dev_files); i++) {
		dev_file = &dev_files[i];
		if (f_name_equal(f_name, dev_file->f_name)) {
			f->f_op = dev_file->f_op;
			ret = 0;
			break;
		}
	}

	return ret;
}
