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
#include <lego/comp_memory.h>
#include <processor/processor.h>

struct pinned_thread_info {
	int cpu;
	struct task_struct *p;
	struct list_head next;
};

static cpumask_t cpu_pinned_mask;
static DEFINE_SPINLOCK(pincpu_lock);
static LIST_HEAD(pinned_thread_list);

#define cpu_pinned(cpu)		cpumask_test_cpu((cpu), &cpu_pinned_mask)

/*
 * Pin the current thread to current running cpu.
 * If this cpu already has an pinned thread, then -EBUSY is returned.
 *
 * After this call, the current thread will run on this cpu exclusively:
 * - will not be migrated
 * - the ONLY thread running on this core
 */
int pin_current_thread_core(void)
{
	int cpu = get_cpu();
	int ret;
	struct pinned_thread_info *info;

	spin_lock(&pincpu_lock);
	if (cpu_pinned(cpu)) {
		ret = -EBUSY;
		goto unlock;
	}

	if (!cpu_active(cpu)) {
		ret = -ENODEV;
		goto unlock;
	}

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		ret = -ENOMEM;
		goto unlock;
	}

	info->cpu = cpu;
	info->p = current;

	list_add(&info->next, &pinned_thread_list);
	cpumask_set_cpu(cpu, &cpu_pinned_mask);

	/*
	 * Remove the cpu from cpu_active_mask,
	 * so scheduler will not schedule anything to it.
	 */
	set_cpus_allowed_ptr(current, get_cpu_mask(cpu));
	set_cpu_active(cpu, false);

	ret = 0;
unlock:
	spin_unlock(&pincpu_lock);
	put_cpu();
	return ret;
}

void print_pinned_threads(void)
{
	struct pinned_thread_info *info;
	int i = 0;

	spin_lock(&pincpu_lock);
	if (list_empty(&pinned_thread_list)) {
		pr_info(" No pinned threads.\n");
		goto unlock;
	}

	list_for_each_entry(info, &pinned_thread_list, next) {
		pr_info("  [%d] Thread[%s:%d] pinned at CPU %d\n",
			i++, info->p->comm, info->p->pid, info->cpu);
	}
unlock:
	spin_unlock(&pincpu_lock);
}

#ifdef CONFIG_CHECK_PINNED_THREADS
void check_pinned_status(void)
{

}
#endif
