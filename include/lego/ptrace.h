/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PTRACE_H_
#define _LEGO_PTRACE_H_

#include <asm/ptrace.h>
#include <lego/sched.h>

#ifndef current_pt_regs
#define current_pt_regs()	task_pt_regs(current)
#endif

static inline int ptrace_reparented(struct task_struct *child)
{
	return !same_thread_group(child->real_parent, child->parent);
}

#endif /* _LEGO_PTRACE_H_ */
