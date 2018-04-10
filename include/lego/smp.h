/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_SMP_H_
#define _LEGO_SMP_H_

#include <lego/sched.h>
#include <lego/preempt.h>

#include <asm/smp.h>

extern unsigned int nr_cpus;

void cpu_up(int cpu, struct task_struct *tidle);

void cpu_online_callback(unsigned int cpu);

void smp_announce(void);
void __init smp_prepare_cpus(unsigned int maxcpus);
void __init smp_init(void);
void __init call_function_init(void);

#define get_cpu()		({ preempt_disable(); smp_processor_id(); })
#define put_cpu()		preempt_enable()

int smpcfd_prepare_cpu(unsigned int cpu);

typedef void (*smp_call_func_t)(void *info);

struct call_single_data {
	struct llist_node llist;
	smp_call_func_t func;
	void *info;
	unsigned int flags;
};

/*
 * Call a function on all other processors
 */
int smp_call_function_single(int cpu, smp_call_func_t func, void *info, int wait);
int smp_call_function(smp_call_func_t func, void *info, int wait);
void smp_call_function_many(const struct cpumask *mask,
			    smp_call_func_t func, void *info, bool wait);

int smp_call_function_any(const struct cpumask *mask,
			  smp_call_func_t func, void *info, int wait);

void generic_smp_call_function_single_interrupt(void);

#endif /* _LEGO_SMP_H_ */
