/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/stat.h>
#include <lego/slab.h>
#include <lego/vmstat.h>
#include <lego/files.h>
#include <lego/uaccess.h>
#include <lego/seq_file.h>
#include <lego/spinlock.h>
#include <lego/kernel_stat.h>
#include <lego/sysinfo.h>

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
	struct manager_sysinfo i;

	/*
	 * XXX:
	 * We should report the memory usage, which is the sum
	 * of from all used memory components.
	 */
	manager_meminfo(&i);

	show_val_kb(m, "MemTotal:       ", i.totalram);
	show_val_kb(m, "MemFree:        ", i.freeram);
	show_val_kb(m, "MemAvailable:   ", i.freeram);

	show_val_kb(m, "PageTables:     ",
		    global_page_state(NR_PAGETABLE));

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
