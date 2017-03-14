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

DEFINE_PER_CPU(struct task_struct *, idle_threads);

/*
 * Initialize an idle thread for a CPU
 */
static void __init init_idle(int cpu)
{
	struct task_struct *tsk;

	tsk = copy_process(CLONE_VM, 0, 0, cpu_to_node(cpu), 0);
	if (!tsk)
		panic("fail to init idle thread for cpu %d\n", cpu);

	sched_init_idle(tsk, cpu);
	per_cpu(idle_threads, cpu) = tsk;
}

static void __init init_idle_threads(void)
{
	int cpu;

	/* CPU0 */
	BUG_ON(!cpu_online(smp_processor_id()));
	per_cpu(idle_threads, smp_processor_id()) = current;

	for_each_present_cpu(cpu) {
		if (!cpu_online(cpu))
			init_idle(cpu);
	}
}

/* Called by boot processor to activate the rest. */
void __init smp_init(void)
{
	int cpu;

	init_idle_threads();

	for_each_present_cpu(cpu) {
		if (!cpu_online(cpu))
			cpu_up(cpu, per_cpu(idle_threads, cpu));
	}
}
