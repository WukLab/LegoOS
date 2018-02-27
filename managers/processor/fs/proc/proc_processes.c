/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/files.h>
#include <lego/sched.h>
#include <lego/seq_file.h>

static int processes_show(struct seq_file *m, void *v)
{
	struct task_struct *p, *t;

	spin_lock(&tasklist_lock);
	for_each_process(p) {
		seq_printf(m, "PID: %d, COMM: %s\n",
			p->pid, p->comm);
		for_each_thread(p, t) {
			if (p == t)
				continue;
			seq_printf(m, "  PID: %d, TGID: %d\n",
				t->pid, t->tgid);
		}
	}
	spin_unlock(&tasklist_lock);

	return 0;
}

static int processes_open(struct file *file)
{
	return single_open(file, processes_show, NULL);
}

static ssize_t processes_write(struct file *f, const char __user *buf,
			       size_t count, loff_t *off)
{
	return -EFAULT;
}

struct file_operations proc_processes_ops = {
	.open		= processes_open,
	.read		= seq_read,
	.write		= processes_write,
	.release	= single_release,
};
