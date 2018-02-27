/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Parameters used by boot setup code
 */

#ifndef _ASM_X86_CURRENT_H_
#define _ASM_X86_CURRENT_H_

#include <lego/compiler.h>
#include <lego/percpu.h>

struct task_struct;

DECLARE_PER_CPU(struct task_struct *, current_task);

static __always_inline struct task_struct *get_current(void)
{
	return this_cpu_read_stable(current_task);
}

#define current get_current()

#endif /* _ASM_X86_CURRENT_H_ */
