/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_SMP_H_
#define _LEGO_SMP_H_

#include <lego/sched.h>
#include <lego/compiler.h>

#include <asm/smp.h>

static inline void cpu_up(int cpu, struct task_struct *tidle)
{
	native_cpu_up(cpu, tidle);
}

void __init smp_prepare_cpus(unsigned int maxcpus);
void __init smp_init(void);

#endif /* _LEGO_SMP_H_ */
