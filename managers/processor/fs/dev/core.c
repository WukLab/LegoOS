/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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
#include <processor/processor.h>
#include <processor/fs.h>

/*
 * Defined managers/processor/fs/stdio.c
 *
 * By default, Lego opens stdin, stdout, stderr
 * for all user program. If they want to open /dev/tty again,
 * it will use the same ops.
 */
extern const struct file_operations stdio_file_op;
extern const struct file_operations random_file_ops;
extern const struct file_operations urandom_file_ops;
extern const struct file_operations null_file_ops;

struct dev_file_struct {
	char f_name[FILENAME_LEN_DEFAULT];
	const struct file_operations *f_op;
};

static struct dev_file_struct dev_files[] = {
	{
		.f_name	= "/dev/tty",
		.f_op	= &stdio_file_op,
	},
	{
		.f_name	= "/dev/random",
		.f_op	= &random_file_ops,
	},
	{
		.f_name	= "/dev/urandom",
		.f_op	= &urandom_file_ops,
	},
	{
		.f_name	= "/dev/null",
		.f_op	= &null_file_ops,
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

loff_t dev_llseek(struct file *file, loff_t offset, int whence)
{
	long ret = -EINVAL;

	switch (whence) {
	case SEEK_END:
		break;
	case SEEK_SET:
	case SEEK_CUR:
		if (offset == 0)
			ret = 0;
		break;

	default:
		WARN_ON(1);
	}

	return ret;
}
