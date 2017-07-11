/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/syscalls.h>

/* Non-implemented system calls get redirected here. */
asmlinkage long sys_ni_syscall(void)
{
	pr_info("%s(CPU%d): current: %d/%s\n",
		__func__, smp_processor_id(), current->pid, current->comm);
	return -ENOSYS;
}

SYSCALL_DEFINE2(testhh, int, foo, long, bar)
{
	return current->pid;
}

/**
 * sys_getpid - return the thread group id of the current process
 *
 * Note, despite the name, this returns the tgid not the pid.  The tgid and
 * the pid are identical unless CLONE_THREAD was specified on clone() in
 * which case the tgid is the same in all threads of the same group.
 *
 * This is SMP safe as current->tgid does not change.
 */
SYSCALL_DEFINE0(getpid)
{
	pr_info("%s(CPU%d): current: %d/%s\n",
		__func__, smp_processor_id(), current->pid, current->comm);
	return current->tgid;
}

/* Thread ID - the internal kernel "pid" */
SYSCALL_DEFINE0(gettid)
{
	pr_info("%s(CPU%d): current: %d/%s\n",
		__func__, smp_processor_id(), current->pid, current->comm);
	return current->pid;
}

/*
 * This section defines SYSCALLs that are only available to processor component
 * We are having this to make the kernel compile
 */
#if !defined(CONFIG_COMP_PROCESSOR) && !defined(CONFIG_COMP_MEMORY)
SYSCALL_DEFINE3(execve,
		const char __user*, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp)
{
	panic("Not right baby.");
	return 0;
}
#endif
