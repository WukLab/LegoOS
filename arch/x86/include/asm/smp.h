/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_SMP_H_
#define _ASM_X86_SMP_H_

#include <lego/percpu.h>

struct task_struct;

int native_cpu_up(int cpu, struct task_struct *tidle);

DECLARE_PER_CPU_READ_MOSTLY(int, cpu_number);
DECLARE_PER_CPU_READ_MOSTLY(int, node_number);

#ifdef CONFIG_SMP
#  define smp_processor_id()	(this_cpu_read(cpu_number))
# ifdef CONFIG_NUMA
#  define smp_node_id()		(this_cpu_read(node_number))
# else
#  define smp_node_id()		0
# endif
#else
#  define smp_processor_id()	0
#  define smp_node_id()		0
#endif

struct smp_ops {
	void (*smp_send_reschedule)(int cpu);

	void (*stop_other_cpus)(int wait);

	void (*send_call_func_ipi)(const struct cpumask *mask);
	void (*send_call_func_single_ipi)(int cpu);
};

extern struct smp_ops smp_ops;

static inline void smp_send_reschedule(int cpu)
{
	smp_ops.smp_send_reschedule(cpu);
}

static inline void smp_send_stop(void)
{
	smp_ops.stop_other_cpus(0);
}

static inline void arch_send_call_function_single_ipi(int cpu)
{
	smp_ops.send_call_func_single_ipi(cpu);
}

static inline void arch_send_call_function_ipi_mask(const struct cpumask *mask)
{
	smp_ops.send_call_func_ipi(mask);
}

#endif /* _ASM_X86_SMP_H_ */
