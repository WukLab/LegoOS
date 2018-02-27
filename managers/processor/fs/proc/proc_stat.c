/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/stat.h>
#include <lego/sched.h>
#include <lego/slab.h>
#include <lego/uaccess.h>
#include <lego/files.h>
#include <lego/seq_file.h>
#include <lego/spinlock.h>
#include <lego/timekeeping.h>
#include <lego/kernel_stat.h>
#include <lego/irqdesc.h>

static int show_stat(struct seq_file *p, void *v)
{
	int i;
	u64 user, nice, system, idle, iowait, irq, softirq, steal;
	u64 guest, guest_nice;
	struct timespec boottime;

	user = nice = system = idle = iowait =
		irq = softirq = steal = 0;
	guest = guest_nice = 0;
	getboottime(&boottime);

	for_each_possible_cpu(i) {
		user += kcpustat_cpu(i).cpustat[CPUTIME_USER];
		nice += kcpustat_cpu(i).cpustat[CPUTIME_NICE];
		system += kcpustat_cpu(i).cpustat[CPUTIME_SYSTEM];
		idle += kcpustat_cpu(i).cpustat[CPUTIME_IDLE];
		iowait += kcpustat_cpu(i).cpustat[CPUTIME_IOWAIT];
		irq += kcpustat_cpu(i).cpustat[CPUTIME_IRQ];
		softirq += kcpustat_cpu(i).cpustat[CPUTIME_SOFTIRQ];
		steal += kcpustat_cpu(i).cpustat[CPUTIME_STEAL];
		guest += kcpustat_cpu(i).cpustat[CPUTIME_GUEST];
		guest_nice += kcpustat_cpu(i).cpustat[CPUTIME_GUEST_NICE];
	}

	seq_put_decimal_ull(p, "cpu  ", cputime_to_clock_t(user));
	seq_put_decimal_ull(p, " ", cputime_to_clock_t(nice));
	seq_put_decimal_ull(p, " ", cputime_to_clock_t(system));
	seq_put_decimal_ull(p, " ", cputime_to_clock_t(idle));
	seq_put_decimal_ull(p, " ", cputime_to_clock_t(iowait));
	seq_put_decimal_ull(p, " ", cputime_to_clock_t(irq));
	seq_put_decimal_ull(p, " ", cputime_to_clock_t(softirq));
	seq_put_decimal_ull(p, " ", cputime_to_clock_t(steal));
	seq_put_decimal_ull(p, " ", cputime_to_clock_t(guest));
	seq_put_decimal_ull(p, " ", cputime_to_clock_t(guest_nice));
	seq_putc(p, '\n');

	for_each_online_cpu(i) {
		/* Copy values here to work around gcc-2.95.3, gcc-2.96 */
		user = kcpustat_cpu(i).cpustat[CPUTIME_USER];
		nice = kcpustat_cpu(i).cpustat[CPUTIME_NICE];
		system = kcpustat_cpu(i).cpustat[CPUTIME_SYSTEM];
		idle = kcpustat_cpu(i).cpustat[CPUTIME_IDLE];
		iowait = kcpustat_cpu(i).cpustat[CPUTIME_IOWAIT];
		irq = kcpustat_cpu(i).cpustat[CPUTIME_IRQ];
		softirq = kcpustat_cpu(i).cpustat[CPUTIME_SOFTIRQ];
		steal = kcpustat_cpu(i).cpustat[CPUTIME_STEAL];
		guest = kcpustat_cpu(i).cpustat[CPUTIME_GUEST];
		guest_nice = kcpustat_cpu(i).cpustat[CPUTIME_GUEST_NICE];
		seq_printf(p, "cpu%d", i);
		seq_put_decimal_ull(p, " ", cputime_to_clock_t(user));
		seq_put_decimal_ull(p, " ", cputime_to_clock_t(nice));
		seq_put_decimal_ull(p, " ", cputime_to_clock_t(system));
		seq_put_decimal_ull(p, " ", cputime_to_clock_t(idle));
		seq_put_decimal_ull(p, " ", cputime_to_clock_t(iowait));
		seq_put_decimal_ull(p, " ", cputime_to_clock_t(irq));
		seq_put_decimal_ull(p, " ", cputime_to_clock_t(softirq));
		seq_put_decimal_ull(p, " ", cputime_to_clock_t(steal));
		seq_put_decimal_ull(p, " ", cputime_to_clock_t(guest));
		seq_put_decimal_ull(p, " ", cputime_to_clock_t(guest_nice));
		seq_putc(p, '\n');
	}

	seq_put_decimal_ull(p, "intr ", (unsigned long long)0);

	seq_printf(p,
		"\nctxt %llu\n"
		"btime %llu\n"
		"processes %lu\n"
		"procs_running %lu\n"
		"procs_blocked %lu\n",
		nr_context_switches(),
		(unsigned long long)boottime.tv_sec,
		total_forks,
		nr_running(),
		nr_iowait());

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
