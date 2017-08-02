/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/files.h>
#include <lego/kernel.h>
#include <processor/include/fs.h>

#include "internal.h"

static int stdio_file_open(struct file *f)
{
	/* already copied for all process during fork() time */
	BUG();
	return 0;
}

/* STDIN, not available */
static ssize_t stdio_file_read(struct file *f, char __user *buf,
				size_t count, loff_t *off)
{
	return -EIO;
}

/* STDOUT and STDERR */
static ssize_t stdio_file_write(struct file *f, const char __user *buf,
				size_t count, loff_t *off)
{
	char *kbuf;
	long ret;

	kbuf = kmalloc(count, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, buf, count)) {
		ret = -EFAULT;
		goto out;
	}

	pr_info("STDOUT: [%s]\n", kbuf);
	ret = count;

out:
	kfree(kbuf);
	return ret;
}

static const struct file_operations stdio_file_op = {
	.open		= stdio_file_open,
	.read		= stdio_file_read,
	.write		= stdio_file_write,
};

struct file stdio_file = {
	.f_name		= "/dev/tty",
	.f_count	= ATOMIC_INIT(1),
	.f_pos_lock	= __SPIN_LOCK_UNLOCKED(f_pos_lock),
	.f_op		= &stdio_file_op,
};
