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
#include <lego/kernel.h>

struct pt_regs;

#ifdef CONFIG_STRACE
void strace_enter(struct pt_regs *regs);
void strace_exit(struct pt_regs *regs);
#else
static inline void strace_enter(struct pt_regs *regs) { }
static inline void strace_exit(struct pt_regs *regs) { }
#endif

typedef void (*strace_call_ptr_t)(unsigned long,
				  unsigned long, unsigned long,
				  unsigned long, unsigned long,
				  unsigned long, unsigned long);

#define STRACE_DEFINE0(sname)					\
	void strace_##sname(void)

#define STRACE_DEFINE1(name, ...) STRACE_DEFINEx(1, __##name, __VA_ARGS__)
#define STRACE_DEFINE2(name, ...) STRACE_DEFINEx(2, __##name, __VA_ARGS__)
#define STRACE_DEFINE3(name, ...) STRACE_DEFINEx(3, __##name, __VA_ARGS__)
#define STRACE_DEFINE4(name, ...) STRACE_DEFINEx(4, __##name, __VA_ARGS__)
#define STRACE_DEFINE5(name, ...) STRACE_DEFINEx(5, __##name, __VA_ARGS__)
#define STRACE_DEFINE6(name, ...) STRACE_DEFINEx(6, __##name, __VA_ARGS__)

#define STRACE_DEFINEx(x, sname, ...)				\
	__STRACE_DEFINEx(x, sname, __VA_ARGS__)

#define __STRACE_DEFINEx(x, name, ...)				\
	static inline void strace##name(unsigned long nr, __MAP(x,__SC_DECL,__VA_ARGS__))

struct strace_flag {
	unsigned long	val;
	const char	*str;
};

void strace_printflags(struct strace_flag *sf, unsigned long flags, unsigned char *buf);

#define SF(val)		{ (unsigned long)val, #val }
#define SEND		{ 0, NULL }




/* TODO: Legacy code: to be removed */
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
