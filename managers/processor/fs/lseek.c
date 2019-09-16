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
#include <processor/fs.h>
#include <processor/processor.h>

/*
 * proc/sys/socket files not implemented yet
 */
static loff_t ni_llseek(struct file *file, loff_t offset, int whence)
{
	long ret = -ESPIPE;
	WARN(1, "This lseek is not implemented yet!\n");
	pr_info("fname: %s\n", file->f_name);
	return ret;
}

loff_t no_llseek(struct file *file, loff_t offset, int whence)
{
	return -ESPIPE;
}

SYSCALL_DEFINE3(lseek, unsigned int, fd, off_t, offset, unsigned int, whence)
{
    struct file *f = fdget(fd);
	long ret;

	syscall_enter("fd: %u\n", fd);

	if (IS_ERR_OR_NULL(f)) {
			pr_info("lseek: file is error or null, %p", (void*)f);
			ret = -EBADF;
			goto out;
	}

	if (whence > SEEK_MAX) {
		pr_info("lseek: invalid lseek");
		ret = -ESPIPE;
		goto put;
	}

	if (f->f_op->llseek)
		ret = f->f_op->llseek(f, offset, whence);
	else
		ret = ni_llseek(f, offset, whence);

put:
	put_file(f);
out:
	syscall_exit(ret);
	return ret;
}
