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
#include <lego/seq_file.h>

#include "../internal.h"

static int devices_system_cpu_online_show(struct seq_file *m, void *v)
{
	char buf[64];

	memset(buf, 0, 64);
	scnprintf(buf, 64, "%*pbl", num_online_cpus(), cpu_online_mask);
	seq_printf(m, "%s\n", buf);

	return 0;
}

static int devices_system_cpu_online_open(struct file *file)
{
	return single_open(file, devices_system_cpu_online_show, NULL);
}

static ssize_t
devices_system_cpu_online_write(struct file *f, const char __user *buf,
				size_t count, loff_t *off)
{
	return -EFAULT;
}

struct file_operations sys_devices_system_cpu_online_ops = {
	.open		= devices_system_cpu_online_open,
	.read		= seq_read,
	.write		= devices_system_cpu_online_write,
	.release	= single_release,
};
