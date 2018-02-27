/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/files.h>
#include <lego/utsname.h>
#include <lego/seq_file.h>

static int version_show(struct seq_file *m, void *v)
{
	seq_printf(m, lego_proc_banner,
		utsname.sysname,
		utsname.release,
		utsname.version);
	return 0;
}

static int version_open(struct file *file)
{
	return single_open(file, version_show, NULL);
}

static ssize_t version_write(struct file *f, const char __user *buf,
			     size_t count, loff_t *off)
{
	return -EFAULT;
}

struct file_operations proc_version_ops = {
	.open		= version_open,
	.read		= seq_read,
	.write		= version_write,
	.release	= single_release,
};
