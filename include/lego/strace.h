/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_STRACE_H_
#define _LEGO_STRACE_H_

#include <lego/types.h>

struct pt_regs;

struct strace {
	struct pt_regs	regs;
	pid_t		pid;
	int		enter_cpu;
};

#ifdef CONFIG_TRACE_SYSCALL
void trace_syscall_enter(void);
void trace_syscall_exit(void);
#else
static inline void trace_syscall_enter(void) { }
static inline void trace_syscall_exit(void) { }
#endif

#endif /* _LEGO_STRACE_H_ */
