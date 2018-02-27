/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_UNWIND_H_
#define _ASM_X86_UNWIND_H_

#include <asm/ptrace.h>
#include <asm/stacktrace.h>
#include <lego/sched.h>

struct unwind_state {
	struct stack_info stack_info;
	unsigned long stack_mask;
	struct task_struct *task;
#ifdef CONFIG_FRAME_POINTER
	unsigned long *bp;
#else
	unsigned long *sp;
#endif
};

void __unwind_start(struct unwind_state *state, struct task_struct *task,
		    struct pt_regs *regs, unsigned long *first_frame);

bool unwind_next_frame(struct unwind_state *state);

static inline void
unwind_start(struct unwind_state *state, struct task_struct *task,
	     struct pt_regs *regs, unsigned long *first_frame)
{
	first_frame = first_frame ? : get_stack_pointer(task, regs);

	__unwind_start(state, task, regs, first_frame);
}

static inline bool unwind_done(struct unwind_state *state)
{
	return state->stack_info.type == STACK_TYPE_UNKNOWN;
}

#ifdef CONFIG_FRAME_POINTER
static inline unsigned long *
unwind_get_return_address_ptr(struct unwind_state *state)
{
	if (unwind_done(state))
		return NULL;
	return state->bp + 1;
}

#else
static inline unsigned long *
unwind_get_return_address_ptr(struct unwind_state *state)
{
	return NULL;
}
#endif

#endif /* _ASM_X86_UNWIND_H_ */
