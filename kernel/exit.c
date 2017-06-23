/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/kernel.h>

void __noreturn do_exit(long code)
{
	struct task_struct *tsk = current;

	if (unlikely(!tsk->pid))
		panic("Attempted to kill the idle task!");

	if (unlikely(in_atomic())) {
		pr_info("note: %s[%d] exited with preempt_count %d\n",
			current->comm, current->pid, preempt_count());
		preempt_count_set(0);
	}

	tsk->exit_code = code;

	preempt_disable();
	do_task_dead();
}
