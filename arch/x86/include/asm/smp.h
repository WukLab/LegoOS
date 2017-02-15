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

#ifndef _LEGO_SMP_H_
#error Please include lego/smp.h instead
#endif

struct task_struct;

int native_cpu_up(int cpu, struct task_struct *tidle);

#endif /* _ASM_X86_SMP_H_ */
