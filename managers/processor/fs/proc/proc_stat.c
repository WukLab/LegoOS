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
#include <lego/seq_file.h>
#include <lego/spinlock.h>

static int show_stat(struct seq_file *p, void *v)
{
	int cpu;

	for_each_online_cpu(cpu) {
		seq_printf(p, "%2d\n", cpu);
	}

	return 0;
}

static ssize_t stat_write(struct file *f, const char __user *buf,
			  size_t count, loff_t *off)
{
	return -EFAULT;
}

static int stat_open(struct file *file)
{
	size_t size = 1024 + 128 * num_online_cpus();

	/* minimum size to display an interrupt count : 2 bytes */
	size += 2 * nr_irqs;
	return single_open_size(file, show_stat, NULL, size);
}

struct file_operations proc_stat_ops = {
	.open		= stat_open,
	.read		= seq_read,
	.write		= stat_write,
	.release	= single_release,
};
