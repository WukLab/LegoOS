/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/utsname.h>
#include <lego/syscalls.h>

/* Non-implemented system calls get redirected here. */
asmlinkage long sys_ni_syscall(void)
{
	unsigned long rax;

	asm volatile (
		"movq %%rax, %0\n\t"
		: "=r" (rax) : :
	);
	pr_info("%s(CPU%d): current: %d/%s, SYSCALL number: %lu\n",
		__func__, smp_processor_id(), current->pid, current->comm, rax);
	return -ENOSYS;
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
	return current->group_leader->pid;
}

/* Thread ID - the internal kernel "pid" */
SYSCALL_DEFINE0(gettid)
{
	pr_info("%s(CPU%d): current: %d/%s\n",
		__func__, smp_processor_id(), current->pid, current->comm);
	return current->pid;
}

/*
 * Accessing ->real_parent is not SMP-safe, it could
 * change from under us.
 * Anyway, it should be enough for us.
 */
SYSCALL_DEFINE0(getppid)
{
	pr_info("%s(CPU%d): current: %d/%s\n",
		__func__, smp_processor_id(), current->pid, current->comm);
	return current->real_parent->pid;
}

/* make sure you are allowed to change @tsk limits before calling this */
int do_prlimit(struct task_struct *tsk, unsigned int resource,
		struct rlimit *new_rlim, struct rlimit *old_rlim)
{
	return -EFAULT;
}

SYSCALL_DEFINE2(setrlimit, unsigned int, resource, struct rlimit __user *, rlim)
{
	struct rlimit new_rlim;

	pr_info("%s(CPU%d): current: %d/%s\n",
		__func__, smp_processor_id(), current->pid, current->comm);
	if (copy_from_user(&new_rlim, rlim, sizeof(*rlim)))
		return -EFAULT;
	return do_prlimit(current, resource, &new_rlim, NULL);
}

SYSCALL_DEFINE2(getrlimit, unsigned int, resource, struct rlimit __user *, rlim)
{
	struct rlimit value;
	int ret;

	pr_info("%s(CPU%d): current: %d/%s\n",
		__func__, smp_processor_id(), current->pid, current->comm);
	ret = do_prlimit(current, resource, NULL, &value);
	if (!ret)
		ret = copy_to_user(rlim, &value, sizeof(*rlim)) ? -EFAULT : 0;

	return ret;
}

SYSCALL_DEFINE1(newuname, struct utsname __user *, name)
{
	pr_info("%s(CPU%d): current: %d/%s\n",
		__func__, smp_processor_id(), current->pid, current->comm);
	if (copy_to_user(name, &utsname, sizeof(*name)))
		return -EFAULT;
	return 0;
}

/*
 * This section defines SYSCALLs that are only available to processor component
 * We are having this to make the kernel compile
 */
#if !defined(CONFIG_COMP_PROCESSOR) && !defined(CONFIG_COMP_MEMORY)
SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	BUG();
}

SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	BUG();
}

SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
	BUG();
}

SYSCALL_DEFINE1(close, unsigned int, fd)
{
	BUG();
}

SYSCALL_DEFINE3(execve,
		const char __user*, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp)
{
	BUG();
}

SYSCALL_DEFINE1(brk, unsigned long, brk)
{
	BUG();	
}

SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags,
		unsigned long, fd, unsigned long, off)
{
	BUG();
}

SYSCALL_DEFINE3(mprotect, unsigned long, start, size_t, len,
		unsigned long, prot)
{
	BUG();
}

SYSCALL_DEFINE2(munmap, unsigned long, addr, size_t, len)
{
	BUG();
}

SYSCALL_DEFINE3(msync, unsigned long, start, size_t, len, int, flags)
{
	BUG();
}
#endif
