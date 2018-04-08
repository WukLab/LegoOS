/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_STRACE_H_
#define _LEGO_STRACE_H_

#include <lego/types.h>
#include <lego/kernel.h>

struct pt_regs;

#ifdef CONFIG_STRACE
void strace_syscall_enter(struct pt_regs *regs);
void strace_syscall_exit(struct pt_regs *regs);

/* Hook for fork() and exit() */
int __fork_processor_strace(struct task_struct *p);
int fork_processor_strace(struct task_struct *p);
void exit_processor_strace(struct task_struct *p);
#else
static inline void strace_syscall_enter(struct pt_regs *regs) { }
static inline void strace_syscall_exit(struct pt_regs *regs) { }

static inline int __fork_processor_strace(struct task_struct *p)
{
	return 0;
}

static inline int fork_processor_strace(struct task_struct *p)
{
	return 0;
}

static inline void exit_processor_strace(struct task_struct *p)
{

}
#endif /* CONFIG_STRACE */

#endif /* _LEGO_STRACE_H_ */
