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
#include <lego/files.h>
#include <lego/uaccess.h>
#include <lego/spinlock.h>
#include <lego/seq_file.h>
#include <processor/fs.h>

#define OVERCOMMIT_GUESS	0
#define OVERCOMMIT_ALWAYS	1
#define OVERCOMMIT_NEVER	2

int sysctl_overcommit_memory = OVERCOMMIT_GUESS;
int sysctl_overcommit_ratio = 50;
unsigned long sysctl_overcommit_kbytes = 0;

static int oc_kbytes_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%lu", sysctl_overcommit_kbytes);
	return 0;
}

static int oc_memory_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d", sysctl_overcommit_memory);
	return 0;
}

static int oc_ratio_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d", sysctl_overcommit_ratio);
	return 0;
}

static ssize_t oc_kbytes_write(struct file *f, const char __user *buf,
			       size_t count, loff_t *off)
{
	pr_debug("%s\n", FUNC);
	return -EFAULT;
}

static ssize_t oc_memory_write(struct file *f, const char __user *buf,
			       size_t count, loff_t *off)
{
	pr_debug("%s\n", FUNC);
	return -EFAULT;
}

static ssize_t oc_ratio_write(struct file *f, const char __user *buf,
			      size_t count, loff_t *off)
{
	pr_debug("%s\n", FUNC);
	return -EFAULT;
}

static int oc_memory_open(struct file *file)
{
	return single_open(file, oc_memory_show, NULL);
}

static int oc_ratio_open(struct file *file)
{
	return single_open(file, oc_ratio_show, NULL);
}

static int oc_kbytes_open(struct file *file)
{
	return single_open(file, oc_kbytes_show, NULL);
}

struct file_operations proc_sys_vm_overcommit_kbytes_ops = {
	.open		= oc_kbytes_open,
	.read		= seq_read,
	.write		= oc_kbytes_write,
	.release	= single_release,
};

struct file_operations proc_sys_vm_overcommit_memory_ops = {
	.open		= oc_memory_open,
	.read		= seq_read,
	.write		= oc_memory_write,
	.release	= single_release,
};

struct file_operations proc_sys_vm_overcommit_ratio_ops = {
	.open		= oc_ratio_open,
	.read		= seq_read,
	.write		= oc_ratio_write,
	.release	= single_release,
};
