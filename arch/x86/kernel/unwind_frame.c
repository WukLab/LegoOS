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

#define FRAME_HEADER_SIZE	(sizeof(long) * 2)

unsigned long unwind_get_return_address(struct unwind_state *state)
{
	unsigned long addr;
	unsigned long *addr_p;

	if (unwind_done(state))
		return 0;
	addr_p = unwind_get_return_address_ptr(state);
	addr = *addr_p;

	return __kernel_text_address(addr) ? addr : 0;
}

static bool update_stack_state(struct unwind_state *state, void *addr,
			       size_t len)
{
	struct stack_info *info = &state->stack_info;

	/*
	 * If addr isn't on the current stack, switch to the next one.
	 *
	 * We may have to traverse multiple stacks to deal with the possibility
	 * that 'info->next_sp' could point to an empty stack and 'addr' could
	 * be on a subsequent stack.
	 */
	while (!on_stack(info, addr, len))
		if (get_stack_info(info->next_sp, state->task, info,
				   &state->stack_mask))
			return false;
	return true;
}

bool unwind_next_frame(struct unwind_state *state)
{
	unsigned long *next_bp;

	if (unwind_done(state))
		return false;

	next_bp = (unsigned long *)*state->bp;

	/* move to the next frame */
	state->bp = next_bp;
	return true;
}

void __unwind_start(struct unwind_state *state, struct task_struct *task,
		    struct pt_regs *regs, unsigned long *first_frame)
{
	memset(state, 0, sizeof(*state));
	state->task = task;

	/* set up the starting stack frame */
	state->bp = get_frame_pointer(task, regs);

	/* initialize stack info and make sure the frame data is accessible */
	get_stack_info(state->bp, state->task, &state->stack_info,
		       &state->stack_mask);
	update_stack_state(state, state->bp, FRAME_HEADER_SIZE);

	/*
	 * The caller can provide the address of the first frame directly
	 * (first_frame) or indirectly (regs->sp) to indicate which stack frame
	 * to start unwinding at.  Skip ahead until we reach it.
	 */
	while (!unwind_done(state) &&
	       (!on_stack(&state->stack_info, first_frame, sizeof(long)) ||
			state->bp < first_frame))
		unwind_next_frame(state);
}
