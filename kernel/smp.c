/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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

#include <asm/numa.h>

/* Setup number of possible processor ids */
int nr_cpu_ids __read_mostly = NR_CPUS;

struct task_struct *idle_threads[NR_CPUS];

struct task_struct *idle_thread_get(unsigned int cpu)
{
	BUG_ON(cpu >= NR_CPUS);
	return idle_threads[cpu];
}

static inline void idle_init(int cpu)
{
	struct task_struct *tsk;

	tsk = copy_process(CLONE_VM, 0, 0, cpu_to_node(cpu), 0);
	if (!tsk)
		panic("fail to init idle thread for cpu %d\n", cpu);
	sprintf(tsk->comm, "swapper/%d", cpu);

	idle_threads[cpu] = tsk;
}

static void init_idle_threads(void)
{
	int cpu;

	for_each_present_cpu(cpu) {
		if (!cpu_online(cpu))
			idle_init(cpu);
	}
}

/* Called by boot processor to activate the rest. */
void __init smp_init(void)
{
	int cpu;

	pr_info("Bringing up secondary CPUs ...\n");

	init_idle_threads();

	for_each_present_cpu(cpu) {
		if (!cpu_online(cpu))
			cpu_up(cpu, idle_thread_get(cpu));
	}
}
