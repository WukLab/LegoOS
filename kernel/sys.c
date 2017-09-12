/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/stat.h>
#include <lego/files.h>
#include <lego/sched.h>
#include <lego/utsname.h>
#include <lego/syscalls.h>

/* Non-implemented system calls get redirected here. */
asmlinkage long sys_ni_syscall(void)
{
	struct pt_regs *regs = current_pt_regs();

	pr_info("NOTICE: Missing syscall nr: %d\n",
		syscall_get_nr(current, regs));
	show_regs(regs);
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
	debug_syscall_print();
	return current->group_leader->pid;
}

/* Thread ID - the internal kernel "pid" */
SYSCALL_DEFINE0(gettid)
{
	debug_syscall_print();
	return current->pid;
}

/*
 * Accessing ->real_parent is not SMP-safe, it could
 * change from under us.
 * Anyway, it should be enough for us.
 */
SYSCALL_DEFINE0(getppid)
{
	debug_syscall_print();
	return current->real_parent->pid;
}

/* make sure you are allowed to change @tsk limits before calling this */
int do_prlimit(struct task_struct *tsk, unsigned int resource,
		struct rlimit *new_rlim, struct rlimit *old_rlim)
{
	struct rlimit *rlim;
	int retval = 0;

	if (resource >= RLIM_NLIMITS)
		return -EINVAL;
	if (new_rlim) {
		if (new_rlim->rlim_cur > new_rlim->rlim_max)
			return -EINVAL;
		if (resource == RLIMIT_NOFILE &&
				new_rlim->rlim_max > NR_OPEN_DEFAULT)
			return -EPERM;
	}

	/* protect tsk->signal and tsk->sighand from disappearing */
	spin_lock(&tasklist_lock);
	if (!tsk->sighand) {
		retval = -ESRCH;
		goto out;
	}

	rlim = tsk->signal->rlim + resource;
	task_lock(tsk->group_leader);
	if (new_rlim) {
		/* Keep the capable check against init_user_ns until
		   cgroups can contain all limits */
		if (new_rlim->rlim_max > rlim->rlim_max) {
			WARN_ON(1);
			retval = -EPERM;
		}
		if (resource == RLIMIT_CPU && new_rlim->rlim_cur == 0) {
			/*
			 * The caller is asking for an immediate RLIMIT_CPU
			 * expiry.  But we use the zero value to mean "it was
			 * never set".  So let's cheat and make it one second
			 * instead
			 */
			new_rlim->rlim_cur = 1;
		}
	}
	if (!retval) {
		if (old_rlim)
			*old_rlim = *rlim;
		if (new_rlim)
			*rlim = *new_rlim;
	}
	task_unlock(tsk->group_leader);

out:
	spin_unlock(&tasklist_lock);
	return retval;
}

SYSCALL_DEFINE2(setrlimit, unsigned int, resource, struct rlimit __user *, rlim)
{
	struct rlimit new_rlim;

	syscall_enter("resource: %d\n", resource);

	if (copy_from_user(&new_rlim, rlim, sizeof(*rlim)))
		return -EFAULT;
	return do_prlimit(current, resource, &new_rlim, NULL);
}

SYSCALL_DEFINE2(getrlimit, unsigned int, resource, struct rlimit __user *, rlim)
{
	struct rlimit value;
	int ret;

	syscall_enter("resource: %d\n", resource);

	ret = do_prlimit(current, resource, NULL, &value);
	if (!ret)
		ret = copy_to_user(rlim, &value, sizeof(*rlim)) ? -EFAULT : 0;

	return ret;
}

SYSCALL_DEFINE1(newuname, struct utsname __user *, name)
{
	debug_syscall_print();
	if (copy_to_user(name, &utsname, sizeof(*name)))
		return -EFAULT;
	return 0;
}

SYSCALL_DEFINE0(getuid)
{
	debug_syscall_print();
	return current_uid();
}

SYSCALL_DEFINE0(geteuid)
{
	debug_syscall_print();
	return current_euid();
}

SYSCALL_DEFINE0(getgid)
{
	debug_syscall_print();
	return current_gid();
}

SYSCALL_DEFINE0(getegid)
{
	debug_syscall_print();
	return current_egid();
}

SYSCALL_DEFINE1(setuid, uid_t, uid)
{
	struct cred *cred = current->cred;

	debug_syscall_print();
	pr_info("%s(): original uid: %u, new uid: %u\n",
		__func__, current_uid(), uid);

	cred->suid = cred->uid = uid;
	cred->fsuid = cred->euid = uid;

	return 0;
}

SYSCALL_DEFINE1(setgid, gid_t, gid)
{
	struct cred *cred = current->cred;

	debug_syscall_print();
	pr_info("%s(): original gid: %u, new gid: %u\n",
		__func__, current_gid(), gid);

	cred->sgid = cred->gid = gid;
	cred->fsgid = cred->egid = gid;

	return 0;
}

#ifndef CONFIG_FUTEX
SYSCALL_DEFINE2(set_robust_list, struct robust_list_head __user *, head,
		size_t, len)
{
	return -ENOSYS;
}

SYSCALL_DEFINE3(get_robust_list, int, pid,
		struct robust_list_head __user * __user *, head_ptr,
		size_t __user *, len_ptr)
{
	return -ENOSYS;
}

SYSCALL_DEFINE6(futex, u32 __user *, uaddr, int, op, u32, val,
		struct timespec __user *, utime, u32 __user *, uaddr2,
		u32, val3)
{
	return -ENOSYS;
}
#endif

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

SYSCALL_DEFINE3(lseek,unsigned int, fd, off_t, offset, unsigned int, whence)
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

SYSCALL_DEFINE5(mremap, unsigned long, addr, unsigned long, old_len,
		unsigned long, new_len, unsigned long, flags,
		unsigned long, new_addr)
{
	BUG();
}

SYSCALL_DEFINE3(msync, unsigned long, start, size_t, len, int, flags)
{
	BUG();
}

SYSCALL_DEFINE3(readv, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	BUG();
}

SYSCALL_DEFINE3(writev, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	BUG();
}

SYSCALL_DEFINE2(newstat, const char __user *, filename,
		struct stat __user *, statbuf)
{
	BUG();
}

SYSCALL_DEFINE2(newlstat, const char __user *, filename,
		struct stat __user *, statbuf)
{
	BUG();
}

SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)
{
	BUG();
}

SYSCALL_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd)
{
	BUG();
}

SYSCALL_DEFINE1(dup, unsigned int, fildes)
{
	BUG();
}

SYSCALL_DEFINE3(fcntl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{	
	BUG();
}

SYSCALL_DEFINE1(checkpoint_process, pid_t, pid)
{
	BUG();
}

SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{
	BUG();
}

SYSCALL_DEFINE1(pcache_flush, void __user *, vaddr)
{
	BUG();
}
#endif
