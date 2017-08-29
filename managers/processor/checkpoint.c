/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/pid.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/syscalls.h>

int checkpoint_thread(struct task_struct *tsk)
{
	pr_info("%s*(): tsk: %d-%d\n", FUNC, tsk->pid, tsk->tgid);
	clear_tsk_thread_flag(tsk, TIF_NEED_CHECKPOINT);
	return 0;
}

static int checkpoint_process(struct task_struct *p)
{
	struct task_struct *t;

	for_each_thread(p, t) {
		pr_info("%s*(): tsk: %d-%d\n", FUNC, t->pid, t->tgid);
		set_tsk_thread_flag(t, TIF_NEED_CHECKPOINT);

		if (!wake_up_state(t, TASK_ALL))
			kick_process(t);
	}

	return 0;
}

SYSCALL_DEFINE1(checkpoint_process, pid_t, pid)
{
	struct task_struct *tsk;
	long ret = 0;

	syscall_enter("pid: %d\n", pid);

	tsk = find_task_by_pid(pid);
	if (!tsk) {
		ret = -ESRCH;
		goto out;
	}

	ret = checkpoint_process(tsk);
out:
	syscall_exit(ret);
	return ret;
}
