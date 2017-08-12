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
#include <lego/kernel_stat.h>

extern void arch_report_meminfo(struct seq_file *m);

static void show_val_kb(struct seq_file *m, const char *s, unsigned long num)
{
	char v[32];
	static const char blanks[7] = {' ', ' ', ' ', ' ',' ', ' ', ' '};
	int len;

	len = num_to_str(v, sizeof(v), num << (PAGE_SHIFT - 10));

	seq_write(m, s, 16);

	if (len > 0) {
		if (len < 8)
			seq_write(m, blanks, 8 - len);

		seq_write(m, v, len);
	}
	seq_write(m, " kB\n", 4);
}

static int meminfo_show(struct seq_file *m, void *v)
{

	show_val_kb(m, "MemTotal:       ", totalram_pages);
	show_val_kb(m, "MemFree:        ", totalram_pages);
	show_val_kb(m, "MemAvailable:   ", totalram_pages);
	arch_report_meminfo(m);

	return 0;
}

static ssize_t meminfo_write(struct file *f, const char __user *buf,
			     size_t count, loff_t *off)
{
	return -EFAULT;
}

static int meminfo_open(struct file *file)
{
	return single_open(file, meminfo_show, NULL);
}

struct file_operations proc_meminfo_ops = {
	.open		= meminfo_open,
	.read		= seq_read,
	.write		= meminfo_write,
	.release	= single_release,
};
