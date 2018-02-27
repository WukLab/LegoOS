/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_SMPBOOT_H_
#define _LEGO_SMPBOOT_H_

#include <lego/sched.h>
#include <lego/cpumask.h>

/**
 * struct smp_hotplug_thread - CPU hotplug related thread descriptor
 * @store:		Pointer to per cpu storage for the task pointers
 * @list:		List head for core management
 * @thread_should_run:	Check whether the thread should run or not. Called with
 *			preemption disabled.
 * @thread_fn:		The associated thread function
 * @create:		Optional setup function, called when the thread gets
 *			created (Not called from the thread context)
 * @setup:		Optional setup function, called when the thread gets
 *			operational the first time
 * @cleanup:		Optional cleanup function, called when the thread
 *			should stop (module exit)
 * @park:		Optional park function, called when the thread is
 *			parked (cpu offline)
 * @unpark:		Optional unpark function, called when the thread is
 *			unparked (cpu online)
 * @cpumask:		Internal state.  To update which threads are unparked,
 *			call smpboot_update_cpumask_percpu_thread().
 * @selfparking:	Thread is not parked by the park function.
 * @thread_comm:	The base name of the thread
 */
struct smp_hotplug_thread {
	struct task_struct __percpu	**store;
	struct list_head		list;
	int				(*thread_should_run)(unsigned int cpu);
	void				(*thread_fn)(unsigned int cpu);
	void				(*create)(unsigned int cpu);
	void				(*setup)(unsigned int cpu);
	void				(*cleanup)(unsigned int cpu, bool online);
	void				(*park)(unsigned int cpu);
	void				(*unpark)(unsigned int cpu);
	cpumask_var_t			cpumask;
	bool				selfparking;
	const char			*thread_comm;
};

int smpboot_register_percpu_thread_cpumask(struct smp_hotplug_thread *plug_thread,
					   const struct cpumask *cpumask);

static inline int
smpboot_register_percpu_thread(struct smp_hotplug_thread *plug_thread)
{
	return smpboot_register_percpu_thread_cpumask(plug_thread,
						      cpu_possible_mask);
}

void smpboot_unregister_percpu_thread(struct smp_hotplug_thread *plug_thread);
int smpboot_update_cpumask_percpu_thread(struct smp_hotplug_thread *plug_thread,
					 const struct cpumask *);

int smpboot_create_threads(unsigned int cpu);
int smpboot_park_threads(unsigned int cpu);
int smpboot_unpark_threads(unsigned int cpu);

#endif /* _LEGO_SMPBOOT_H_ */
