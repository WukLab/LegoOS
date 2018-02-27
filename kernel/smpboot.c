/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file has some convenient APIs to create daemon kernel threads.
 * It is used by a lot subsystems. For exmaple, stop-machine, watchdog.
 *
 * Lego does not support cpu hotplug. So, it is just really creation only.
 */

#include <lego/mutex.h>
#include <lego/kthread.h>
#include <lego/smpboot.h>

#include <asm/numa.h>

static LIST_HEAD(hotplug_threads);
static DEFINE_MUTEX(smpboot_threads_lock);

struct smpboot_thread_data {
	unsigned int			cpu;
	unsigned int			status;
	struct smp_hotplug_thread	*ht;
};

enum {
	HP_THREAD_NONE = 0,
	HP_THREAD_ACTIVE,
	HP_THREAD_PARKED,
};

/**
 * smpboot_thread_fn - percpu hotplug thread loop function
 * @data:	thread data pointer
 *
 * Checks for thread stop and park conditions. Calls the necessary
 * setup, cleanup, park and unpark functions for the registered
 * thread.
 *
 * Returns 1 when the thread should exit, 0 otherwise.
 */
static int smpboot_thread_fn(void *data)
{
	struct smpboot_thread_data *td = data;
	struct smp_hotplug_thread *ht = td->ht;

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		preempt_disable();
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);
			preempt_enable();
			/* cleanup must mirror setup */
			if (ht->cleanup && td->status != HP_THREAD_NONE)
				ht->cleanup(td->cpu, cpu_online(td->cpu));
			kfree(td);
			return 0;
		}

		if (kthread_should_park()) {
			__set_current_state(TASK_RUNNING);
			preempt_enable();
			if (ht->park && td->status == HP_THREAD_ACTIVE) {
				BUG_ON(td->cpu != smp_processor_id());
				ht->park(td->cpu);
				td->status = HP_THREAD_PARKED;
			}
			kthread_parkme();
			/* We might have been woken for stop */
			continue;
		}

		BUG_ON(td->cpu != smp_processor_id());

		/* Check for state change setup */
		switch (td->status) {
		case HP_THREAD_NONE:
			__set_current_state(TASK_RUNNING);
			preempt_enable();
			if (ht->setup)
				ht->setup(td->cpu);
			td->status = HP_THREAD_ACTIVE;
			continue;

		case HP_THREAD_PARKED:
			__set_current_state(TASK_RUNNING);
			preempt_enable();
			if (ht->unpark)
				ht->unpark(td->cpu);
			td->status = HP_THREAD_ACTIVE;
			continue;
		}

		if (!ht->thread_should_run(td->cpu)) {
			preempt_enable_no_resched();
			schedule();
		} else {
			__set_current_state(TASK_RUNNING);
			preempt_enable();
			ht->thread_fn(td->cpu);
		}
	}
}

static int
__smpboot_create_thread(struct smp_hotplug_thread *ht, unsigned int cpu)
{
	struct task_struct *tsk = *per_cpu_ptr(ht->store, cpu);
	struct smpboot_thread_data *td;

	if (tsk)
		return 0;

	td = kzalloc_node(sizeof(*td), GFP_KERNEL, cpu_to_node(cpu));
	if (!td)
		return -ENOMEM;
	td->cpu = cpu;
	td->ht = ht;

	tsk = kthread_create_on_cpu(smpboot_thread_fn, td, cpu,
				    ht->thread_comm);
	if (IS_ERR(tsk)) {
		kfree(td);
		return PTR_ERR(tsk);
	}

	/*
	 * Wake up the thread and park the thread,
	 * so that it could start right on the CPU when it is available
	 */
	kthread_park(tsk);

	get_task_struct(tsk);
	*per_cpu_ptr(ht->store, cpu) = tsk;
	if (ht->create) {
		/*
		 * Make sure that the task has actually scheduled out
		 * into park position, before calling the create
		 * callback. At least the migration thread callback
		 * requires that the task is off the runqueue.
		 */
		if (!wait_task_inactive(tsk, TASK_PARKED))
			WARN_ON(1);
		else
			ht->create(cpu);
	}
	return 0;
}

int smpboot_create_threads(unsigned int cpu)
{
	struct smp_hotplug_thread *cur;
	int ret = 0;

	mutex_lock(&smpboot_threads_lock);
	list_for_each_entry(cur, &hotplug_threads, list) {
		ret = __smpboot_create_thread(cur, cpu);
		if (ret)
			break;
	}
	mutex_unlock(&smpboot_threads_lock);
	return ret;
}

static void smpboot_unpark_thread(struct smp_hotplug_thread *ht, unsigned int cpu)
{
	struct task_struct *tsk = *per_cpu_ptr(ht->store, cpu);

	if (!ht->selfparking)
		kthread_unpark(tsk);
}

int smpboot_unpark_threads(unsigned int cpu)
{
	struct smp_hotplug_thread *cur;

	mutex_lock(&smpboot_threads_lock);
	list_for_each_entry(cur, &hotplug_threads, list)
		if (cpumask_test_cpu(cpu, cur->cpumask))
			smpboot_unpark_thread(cur, cpu);
	mutex_unlock(&smpboot_threads_lock);
	return 0;
}

static void smpboot_park_thread(struct smp_hotplug_thread *ht, unsigned int cpu)
{
	struct task_struct *tsk = *per_cpu_ptr(ht->store, cpu);

	if (tsk && !ht->selfparking)
		kthread_park(tsk);
}

int smpboot_park_threads(unsigned int cpu)
{
	struct smp_hotplug_thread *cur;

	mutex_lock(&smpboot_threads_lock);
	list_for_each_entry_reverse(cur, &hotplug_threads, list)
		smpboot_park_thread(cur, cpu);
	mutex_unlock(&smpboot_threads_lock);
	return 0;
}

static void smpboot_destroy_threads(struct smp_hotplug_thread *ht)
{
	unsigned int cpu;

	/* We need to destroy also the parked threads of offline cpus */
	for_each_possible_cpu(cpu) {
		struct task_struct *tsk = *per_cpu_ptr(ht->store, cpu);

		if (tsk) {
			kthread_stop(tsk);
			put_task_struct(tsk);
			*per_cpu_ptr(ht->store, cpu) = NULL;
		}
	}
}

/**
 * smpboot_register_percpu_thread_cpumask - Register a per_cpu thread related
 * 					    to hotplug
 * @plug_thread:	Hotplug thread descriptor
 * @cpumask:		The cpumask where threads run
 *
 * Creates and starts the threads on all online cpus.
 */
int smpboot_register_percpu_thread_cpumask(struct smp_hotplug_thread *plug_thread,
					   const struct cpumask *cpumask)
{
	unsigned int cpu;
	int ret = 0;

	cpumask_copy(plug_thread->cpumask, cpumask);

	mutex_lock(&smpboot_threads_lock);
	for_each_online_cpu(cpu) {
		ret = __smpboot_create_thread(plug_thread, cpu);
		if (ret) {
			smpboot_destroy_threads(plug_thread);
			goto out;
		}
		if (cpumask_test_cpu(cpu, cpumask))
			smpboot_unpark_thread(plug_thread, cpu);
	}
	list_add(&plug_thread->list, &hotplug_threads);
out:
	mutex_unlock(&smpboot_threads_lock);
	return ret;
}

/**
 * smpboot_unregister_percpu_thread - Unregister a per_cpu thread related to hotplug
 * @plug_thread:	Hotplug thread descriptor
 *
 * Stops all threads on all possible cpus.
 */
void smpboot_unregister_percpu_thread(struct smp_hotplug_thread *plug_thread)
{
	mutex_lock(&smpboot_threads_lock);
	list_del(&plug_thread->list);
	smpboot_destroy_threads(plug_thread);
	mutex_unlock(&smpboot_threads_lock);
}

/**
 * smpboot_update_cpumask_percpu_thread - Adjust which per_cpu hotplug threads stay parked
 * @plug_thread:	Hotplug thread descriptor
 * @new:		Revised mask to use
 *
 * The cpumask field in the smp_hotplug_thread must not be updated directly
 * by the client, but only by calling this function.
 * This function can only be called on a registered smp_hotplug_thread.
 */
int smpboot_update_cpumask_percpu_thread(struct smp_hotplug_thread *plug_thread,
					 const struct cpumask *new)
{
	struct cpumask *old = plug_thread->cpumask;
	cpumask_var_t tmp;
	unsigned int cpu;

	mutex_lock(&smpboot_threads_lock);

	/* Park threads that were exclusively enabled on the old mask. */
	cpumask_andnot(tmp, old, new);
	for_each_cpu_and(cpu, tmp, cpu_online_mask)
		smpboot_park_thread(plug_thread, cpu);

	/* Unpark threads that are exclusively enabled on the new mask. */
	cpumask_andnot(tmp, new, old);
	for_each_cpu_and(cpu, tmp, cpu_online_mask)
		smpboot_unpark_thread(plug_thread, cpu);

	cpumask_copy(old, new);

	mutex_unlock(&smpboot_threads_lock);

	return 0;
}
