/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "smp: " fmt

#include <lego/smp.h>
#include <lego/kernel.h>
#include <lego/cpumask.h>

struct task_struct idle_threads[NR_CPUS];

struct task_struct *idle_thread_get(unsigned int cpu)
{
	struct task_struct *tsk = &idle_threads[cpu];

	BUG_ON(!tsk);
	return tsk;
}

/* Called by boot processor to activate the rest. */
void __init smp_init(void)
{
	int cpu;

	pr_info("Bringing up secondary CPUs ...\n");

	for_each_present_cpu(cpu) {
		if (!cpu_online(cpu))
			cpu_up(cpu, idle_thread_get(cpu));
	}
}
