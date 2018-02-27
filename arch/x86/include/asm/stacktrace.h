/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_STACKTRACE_H_
#define _ASM_X86_STACKTRACE_H_

#include <asm/page.h>
#include <asm/ptrace.h>
#include <lego/sched.h>

enum stack_type {
	STACK_TYPE_UNKNOWN,
	STACK_TYPE_TASK,
	STACK_TYPE_IRQ,
	STACK_TYPE_SOFTIRQ,
	STACK_TYPE_EXCEPTION,
	STACK_TYPE_EXCEPTION_LAST = STACK_TYPE_EXCEPTION + N_EXCEPTION_STACKS-1,
};

struct stack_info {
	enum stack_type type;
	unsigned long *begin;
	unsigned long *end;
	unsigned long *next_sp;
};

static inline bool on_stack(struct stack_info *info, void *addr, size_t len)
{
	void *begin = info->begin;
	void *end   = info->end;

	return (info->type != STACK_TYPE_UNKNOWN &&
		addr >= begin && addr < end &&
		addr + len > begin && addr + len <= end);
}

#ifdef CONFIG_FRAME_POINTER
static inline unsigned long *
get_frame_pointer(struct task_struct *task, struct pt_regs *regs)
{
	if (regs)
		return (unsigned long *)regs->bp;

	if (task == current)
		return __builtin_frame_address(0);

	return (unsigned long *)((struct inactive_task_frame *)task->thread.sp)->bp;
}
#else
static inline unsigned long *
get_frame_pointer(struct task_struct *task, struct pt_regs *regs)
{
	return NULL;
}
#endif /* CONFIG_FRAME_POINTER */

static inline unsigned long *
get_stack_pointer(struct task_struct *task, struct pt_regs *regs)
{
	if (regs)
		return (unsigned long *)kernel_stack_pointer(regs);

	if (task == current)
		return __builtin_frame_address(0);

	return (unsigned long *)task->thread.sp;
}

/*
 * The form of the top of the frame on the stack
 *
 *  return address
 *  previous rbp
 *              <------%rbp ( == __builtin_frame_address(0))
 *  ...
 *  local var
 *  ...
 *              <------%rsp
 */
struct stack_frame {
	struct stack_frame *next_frame;
	unsigned long return_address;
};

static inline unsigned long caller_frame_pointer(void)
{
	struct stack_frame *frame;

	frame = __builtin_frame_address(0);

#ifdef CONFIG_FRAME_POINTER
	frame = frame->next_frame;
#endif

	return (unsigned long)frame;
}

int get_stack_info(unsigned long *stack, struct task_struct *task,
		   struct stack_info *info, unsigned long *visit_mask);

#endif /* _ASM_X86_STACKTRACE_H_ */
