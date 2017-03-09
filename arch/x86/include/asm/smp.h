/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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

#ifdef CONFIG_SMP
#define smp_processor_id()	(this_cpu_read(cpu_number))
#else
#define smp_processor_id()	0
#endif

#endif /* _ASM_X86_SMP_H_ */
