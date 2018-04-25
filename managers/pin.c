/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/smp.h>
#include <lego/slab.h>
#include <lego/kernel.h>
#include <lego/string.h>
#include <lego/fit_ibapi.h>
#include <lego/cpumask.h>
#include <lego/comp_memory.h>
#include <processor/processor.h>

struct pinned_thread_info {
	int cpu;
	struct task_struct *p;
	struct list_head next;
};

static DEFINE_SPINLOCK(pincpu_lock);
static LIST_HEAD(pinned_thread_list);
static int cpu_position = -1;
static bool stop_pin = false;

int get_next_cpu_position(void)
{
	int cpu;

	spin_lock(&pincpu_lock);
	cpu = cpumask_next(cpu_position, cpu_active_mask);
	cpu_position = cpu;
	spin_unlock(&pincpu_lock);

	return cpu;
}

int pin_current_thread_to_cpu(int cpu)
{
	struct pinned_thread_info *info;
	struct task_struct *p = current;

	if (stop_pin) {
		WARN(1, "Too late to pin\n");
		return -EFAULT;
	}

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	info->cpu = cpu;
	info->p = p;

	spin_lock(&pincpu_lock);
	list_add(&info->next, &pinned_thread_list);
	spin_unlock(&pincpu_lock);

	set_cpus_allowed_ptr(p, get_cpu_mask(cpu));
	set_cpu_active(cpu, false);

	return 0;
}

/*
 * Pin the current thread an active CPU.
 * The CPU is chosen from cpu_acitve_mask
 *
 * After this call, the thread will run on that CPU exclusively:
 * - will not be migrated
 * - the ONLY thread running on this core
 *
 * Return 0 on success.
 */
int pin_current_thread(void)
{
	int cpu = smp_processor_id();
	return pin_current_thread_to_cpu(cpu);
}

void pin_registered_threads(void)
{
	struct task_struct *p;
	struct pinned_thread_info *info;
	int cpu, i = 0;

	spin_lock(&pincpu_lock);

	if (stop_pin)
		goto unlock;

	if (list_empty(&pinned_thread_list)) {
		pr_info(" No threads registered to pin.\n");
		goto unlock;
	}

	list_for_each_entry(info, &pinned_thread_list, next) {
		p = info->p;
		cpu = info->cpu;

		pr_info("  [%d] Thread[%s:%d] pinned at CPU %d\n",
			i++, p->comm, p->pid, cpu);
	}

unlock:
	stop_pin = true;
	spin_unlock(&pincpu_lock);
}
