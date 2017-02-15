/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Thread_info sits in the lowest base of the kernel stack.
 * And we use this to calculate the pointer to the task_struct,
 * which is the current.
 *
 * To have thread_info per cpu, we are able to get the current macro
 * in a per cpu base. Anyway, unlike Linux which now uses a per-cpu
 * current variable.
 */

#ifndef _ASM_X86_THREAD_INFO_H_
#define _ASM_X86_THREAD_INFO_H_

#ifndef __ASSEMBLY__

#include <asm/page.h>

struct task_struct;

struct thread_info {
	struct task_struct	*task;
	__u32			flags;
	__u32			status;
	__u32			cpu;
};

static inline struct thread_info *current_thread_info(void)
{
	struct thread_info *ti;
	asm volatile (
		"andq %%rsp, %0"
		: "=r" (ti)
		: "0" (~((unsigned long)THREAD_SIZE-1))
	);
	return ti;
}

static inline unsigned long current_stack_pointer(void)
{
	unsigned long sp;
	asm volatile (
		"movq %%rsp, %0"
		: "=g" (sp)
	);
	return sp;
}
#endif /* __ASSEMBLY__ */

#define INIT_THREAD_INFO(tsk)	\
{				\
	.task		= &tsk,	\
	.flags		= 0,	\
	.cpu		= 0,	\
}

#define init_thread_info	(init_thread_union.thread_info)
#define init_stack		(init_thread_union.stack)

#endif /* _ASM_X86_THREAD_INFO_H_ */
