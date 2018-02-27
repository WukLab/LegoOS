/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/unwind.h>
#include <asm/stacktrace.h>

#include <lego/string.h>
#include <lego/sections.h>

unsigned long unwind_get_return_address(struct unwind_state *state)
{
	if (unwind_done(state))
		return 0;

	return *state->sp;
}

bool unwind_next_frame(struct unwind_state *state)
{
	struct stack_info *info = &state->stack_info;

	if (unwind_done(state))
		return false;

	do {
		for (state->sp++; state->sp < info->end; state->sp++)
			if (__kernel_text_address(*state->sp))
				return true;

		state->sp = info->next_sp;

	} while (!get_stack_info(state->sp, state->task, info,
				 &state->stack_mask));

	return false;
}

void __unwind_start(struct unwind_state *state, struct task_struct *task,
		    struct pt_regs *regs, unsigned long *first_frame)
{
	memset(state, 0, sizeof(*state));

	state->task = task;
	state->sp   = first_frame;

	get_stack_info(first_frame, state->task, &state->stack_info,
		       &state->stack_mask);

	/*
	 * The caller can provide the address of the first frame directly
	 * (first_frame) or indirectly (regs->sp) to indicate which stack frame
	 * to start unwinding at.  Skip ahead until we reach it.
	 */
	if (!unwind_done(state) &&
	    (!on_stack(&state->stack_info, first_frame, sizeof(long)) ||
	    !__kernel_text_address(*first_frame)))
		unwind_next_frame(state);
}
