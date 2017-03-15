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

void do_exit(long code)
{
	struct task_struct *tsk = current;

	if (unlikely(!tsk->pid))
		panic("Attempted to kill the idle task!");

	tsk->exit_code = code;

	do_task_dead();
}
