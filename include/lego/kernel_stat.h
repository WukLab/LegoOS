/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_KERNEL_STAT_H_
#define _LEGO_KERNEL_STAT_H_

#include <lego/percpu.h>

/*
 * 'kernel_stat.h' contains the definitions needed for doing
 * some kernel statistics (CPU usage, context switches ...),
 * used by rstatd/perfmeter
 */

enum cpu_usage_stat {
	CPUTIME_USER,
	CPUTIME_NICE,
	CPUTIME_SYSTEM,
	CPUTIME_SOFTIRQ,
	CPUTIME_IRQ,
	CPUTIME_IDLE,
	CPUTIME_IOWAIT,
	CPUTIME_STEAL,
	CPUTIME_GUEST,
	CPUTIME_GUEST_NICE,
	NR_STATS,
};

struct kernel_cpustat {
	u64 cpustat[NR_STATS];
};

DECLARE_PER_CPU(struct kernel_cpustat, kernel_cpustat);

#define kcpustat_this_cpu	this_cpu_ptr(&kernel_cpustat)
#define kcpustat_cpu(cpu)	per_cpu(kernel_cpustat, cpu)

void account_user_time(struct task_struct *, cputime_t, cputime_t);
void account_system_time(struct task_struct *, cputime_t, cputime_t);
void account_idle_time(cputime_t);
void account_process_tick(struct task_struct *, int user);

/* scheduler */
unsigned long long nr_context_switches(void);
unsigned long nr_running(void);
unsigned long nr_iowait(void);

#endif /* _LEGO_KERNEL_STAT_H_ */
