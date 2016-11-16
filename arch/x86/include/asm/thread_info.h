/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_THREAD_INFO_H_
#define _ASM_X86_THREAD_INFO_H_

/*
 * TOP_OF_KERNEL_STACK_PADDING is a number of unused bytes that we
 * reserve at the top of the kernel stack.  We do it because of a nasty
 * 32-bit corner case.  On x86_32, the hardware stack frame is
 * variable-length.  Except for vm86 mode, struct pt_regs assumes a
 * maximum-length frame.  If we enter from CPL 0, the top 8 bytes of
 * pt_regs don't actually exist.  Ordinarily this doesn't matter, but it
 * does in at least one case:
 *
 * If we take an NMI early enough in SYSENTER, then we can end up with
 * pt_regs that extends above sp0.  On the way out, in the espfix code,
 * we can read the saved SS value, but that value will be above sp0.
 * Without this offset, that can result in a page fault.  (We are
 * careful that, in this case, the value we read doesn't matter.)
 *
 * In vm86 mode, the hardware frame is much longer still, so add 16
 * bytes to make room for the real-mode segments.
 *
 * x86_64 has a fixed-length stack frame.
 */
#ifdef CONFIG_X86_32
# ifdef CONFIG_VM86
#  define TOP_OF_KERNEL_STACK_PADDING 16
# else
#  define TOP_OF_KERNEL_STACK_PADDING 8
# endif
#else
# define TOP_OF_KERNEL_STACK_PADDING 0
#endif

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
