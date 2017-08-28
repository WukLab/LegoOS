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
#include <lego/syscalls.h>

int checkpoint_thread(struct task_struct *tsk)
{
	clear_tsk_need_checkpoint(tsk);
	return 0;
}

static int __checkpoint_process(struct task_struct *tsk)
{
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

	ret = __checkpoint_process(tsk);
out:
	syscall_exit(ret);
	return ret;
}
