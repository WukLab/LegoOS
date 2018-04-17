/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/stat.h>
#include <lego/files.h>
#include <lego/sched.h>
#include <lego/getcpu.h>
#include <lego/utsname.h>
#include <lego/syscalls.h>
#include <lego/sysinfo.h>
#include <lego/waitpid.h>
#include <lego/timekeeping.h>
#include <processor/pcache.h>
#include <processor/fs.h>
#include <uapi/sysinfo.h>

#include <asm/numa.h>

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

SYSCALL_DEFINE0(getpgrp)
{
	return current->group_leader->pid;
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

/*
 * TODO:
 * This is a vDSO syscall in Linux.
 * If later on we found applications use this syscall a lot, we should probably
 * add vDSO support.
 */
SYSCALL_DEFINE3(getcpu, unsigned __user *, cpup, unsigned __user *, nodep,
		struct getcpu_cache __user *, unused)
{
	int err = 0;
	int cpu = smp_processor_id();

	if (cpup)
		err |= put_user(cpu, cpup);
	if (nodep)
		err |= put_user(cpu_to_node(cpu), nodep);
	return err ? -EFAULT : 0;
}

/*
 * It would make sense to put struct rusage in the task_struct,
 * except that would make the task_struct be *really big*.  After
 * task_struct gets moved into malloc'ed memory, it would
 * make sense to do this.  It will make moving the rest of the information
 * a lot simpler!  (Which we're not doing right now because we're not
 * measuring them yet).
 *
 * When sampling multiple threads for RUSAGE_SELF, under SMP we might have
 * races with threads incrementing their own counters.  But since word
 * reads are atomic, we either get new values or old values and we don't
 * care which for the sums.  We always take the siglock to protect reading
 * the c* fields from p->signal from races with exit.c updating those
 * fields when reaping, so a sample either gets all the additions of a
 * given child after it's reaped, or none so this sample is before reaping.
 *
 * Locking:
 * We need to take the siglock for CHILDEREN, SELF and BOTH
 * for  the cases current multithreaded, non-current single threaded
 * non-current multithreaded.  Thread traversal is now safe with
 * the siglock held.
 * Strictly speaking, we donot need to take the siglock if we are current and
 * single threaded,  as no one else can take our signal_struct away, no one
 * else can  reap the  children to update signal->c* counters, and no one else
 * can race with the signal-> fields. If we do not take any lock, the
 * signal-> fields could be read out of order while another thread was just
 * exiting. So we should  place a read memory barrier when we avoid the lock.
 * On the writer side,  write memory barrier is implied in  __exit_signal
 * as __exit_signal releases  the siglock spinlock after updating the signal->
 * fields. But we don't do this yet to keep things simple.
 *
 */

/* TODO no accounting yet */
static void accumulate_thread_rusage(struct task_struct *t, struct rusage *r)
{
	r->ru_nvcsw += t->nvcsw;
	r->ru_nivcsw += t->nivcsw;
	r->ru_minflt += 0;
	r->ru_majflt += 0;
	r->ru_inblock += 0;
	r->ru_oublock += 0;
}

/* TODO: check if this is correct */
void task_cputime_adjusted(struct task_struct *p, cputime_t *ut, cputime_t *st)
{
	*ut = p->utime;
	*st = p->stime;
}

/* TODO */
void thread_group_cputime_adjusted(struct task_struct *p, cputime_t *ut, cputime_t *st)
{
	*ut = 0;
	*st = 0;
}

/* TODO */
static inline void setmax_mm_hiwater_rss(unsigned long *maxrss,
					 struct mm_struct *mm)
{
}

static void k_getrusage(struct task_struct *p, int who, struct rusage *r)
{
	struct task_struct *t;
	unsigned long flags;
	cputime_t tgutime, tgstime, utime, stime;
	unsigned long maxrss = 0;

	memset((char *)r, 0, sizeof (*r));
	utime = stime = 0;

	if (who == RUSAGE_THREAD) {
		task_cputime_adjusted(current, &utime, &stime);
		accumulate_thread_rusage(p, r);
		maxrss = p->signal->maxrss;
		goto out;
	}

	if (!lock_task_sighand(p, &flags))
		return;

	switch (who) {
	case RUSAGE_BOTH:
	case RUSAGE_CHILDREN:
		utime = p->signal->cutime;
		stime = p->signal->cstime;
		r->ru_nvcsw = p->signal->cnvcsw;
		r->ru_nivcsw = p->signal->cnivcsw;
		r->ru_minflt = p->signal->cmin_flt;
		r->ru_majflt = p->signal->cmaj_flt;
		r->ru_inblock = p->signal->cinblock;
		r->ru_oublock = p->signal->coublock;
		maxrss = p->signal->cmaxrss;

		if (who == RUSAGE_CHILDREN)
			break;

	case RUSAGE_SELF:
		thread_group_cputime_adjusted(p, &tgutime, &tgstime);
		utime += tgutime;
		stime += tgstime;
		r->ru_nvcsw = p->signal->cnvcsw;
		r->ru_nivcsw = p->signal->cnivcsw;
		r->ru_minflt = p->signal->cmin_flt;
		r->ru_majflt = p->signal->cmaj_flt;
		r->ru_inblock = p->signal->cinblock;
		r->ru_oublock = p->signal->coublock;
		if (maxrss < p->signal->maxrss)
			maxrss = p->signal->maxrss;
		t = p;
		do {
			accumulate_thread_rusage(t, r);
		} while_each_thread(p, t);
		break;

	default:
		BUG();
	}
	unlock_task_sighand(p, &flags);

out:
	cputime_to_timeval(utime, &r->ru_utime);
	cputime_to_timeval(stime, &r->ru_stime);

	if (who != RUSAGE_CHILDREN) {
		struct mm_struct *mm = get_task_mm(p);

		if (mm) {
			setmax_mm_hiwater_rss(&maxrss, mm);
			mmput(mm);
		}
	}
	r->ru_maxrss = maxrss * (PAGE_SIZE / 1024); /* convert pages to KBs */
}

int getrusage(struct task_struct *p, int who, struct rusage __user *ru)
{
	struct rusage r;

	k_getrusage(p, who, &r);
	return copy_to_user(ru, &r, sizeof(r)) ? -EFAULT : 0;
}

SYSCALL_DEFINE2(getrusage, int, who, struct rusage __user *, ru)
{
	if (who != RUSAGE_SELF && who != RUSAGE_CHILDREN &&
	    who != RUSAGE_THREAD)
		return -EINVAL;
	return getrusage(current, who, ru);
}

/**
 * do_sysinfo - fill in sysinfo struct
 * @info: pointer to buffer to fill
 */
static int do_sysinfo(struct sysinfo *info)
{
	struct manager_sysinfo val;
	struct timespec tp;

	memset(info, 0, sizeof(struct sysinfo));

	get_monotonic_boottime(&tp);
	info->uptime = tp.tv_sec + (tp.tv_nsec ? 1 : 0);

	info->procs = nr_threads;

	manager_meminfo(&val);

	info->uptime = val.uptime;
	info->loads[0] = val.loads[0];
	info->loads[1] = val.loads[1];
	info->loads[2] = val.loads[2];
	info->totalram = val.totalram;
	info->freeram = val.freeram;
	info->mem_unit = val.mem_unit;

	return 0;	
}

SYSCALL_DEFINE1(sysinfo, struct sysinfo __user *, info)
{
	struct sysinfo k_info;

	do_sysinfo(&k_info);

	if (copy_to_user(info, &k_info, sizeof(struct sysinfo)))
		return -EFAULT;
	
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

SYSCALL_DEFINE1(pcache_stat, struct pcache_stat __user *, statbuf)
{
	BUG();
}

SYSCALL_DEFINE2(access, const char __user *, filename, int, mode)
{
	BUG();
}

SYSCALL_DEFINE3(getcpu, unsigned __user *, cpup, unsigned __user *, nodep,
		struct getcpu_cache __user *, unused)
{
	BUG();
}

SYSCALL_DEFINE5(waitid, int, which, pid_t, upid, struct siginfo __user *,
		infop, int, options, struct rusage __user *, ru)
{
	BUG();
}

SYSCALL_DEFINE4(wait4, pid_t, upid, int __user *, stat_addr,
		int, options, struct rusage __user *, ru)
{
	BUG();
}

SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
		unsigned long, arg4, unsigned long, arg5)
{
	BUG();
}
#endif

/*
 * Just to make the kernel compile
 */
#ifndef CONFIG_SOCKET_SYSCALL

/*
 * Temporary fix:
 * Now we can opt-out socket syscall from processor.
 * Later on, if socket is supported by default, we should
 * remove the following code.
 */
#ifdef CONFIG_COMP_PROCESSOR
static int dummy_sock_open(struct file *f)
{
	return 0;
}

static ssize_t dummy_sock_read(struct file *f, char __user *buf,
			       size_t count, loff_t *off)
{
	return 0;
}

static ssize_t dummy_sock_write(struct file *f, const char __user *buf,
				size_t count, loff_t *off)
{
	return 0;
}

struct file_operations dummy_sock_ops = {
	.open	= dummy_sock_open,
	.read	= dummy_sock_read,
	.write	= dummy_sock_write,
};

SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
	int sockfd;
	struct file *dummy_file;

	sockfd = alloc_fd(current->files, "/sock/dummy");
	if (sockfd < 0)
		return sockfd;

	dummy_file = fdget(sockfd);
	dummy_file->f_mode = FMODE_READ;
	dummy_file->f_flags = O_RDONLY;
	dummy_file->f_op = &dummy_sock_ops;

	put_file(dummy_file);

	pr_info("CPU%d PID%d-%s Dummy Socket: %d\n",
		smp_processor_id(), current->pid, current->comm, sockfd);
	return sockfd;
}

SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr,
		int, addrlen)
{
	pr_info("CPU%d PID%d-%s Dummy Connect: %d\n",
		smp_processor_id(), current->pid, current->comm, fd);
	return -ECONNREFUSED;
}
#else
SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
	BUG();
}

SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr,
		int, addrlen)
{
	BUG();
}
#endif	/* CONFIG_COMP_PROCESSOR */

SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname,
		char __user *, optval, int, optlen)
{
	BUG();
}

SYSCALL_DEFINE5(getsockopt, int, fd, int, level, int, optname,
		char __user *, optval, int __user *, optlen)
{
	BUG();
}

SYSCALL_DEFINE3(getsockname, int, fd, struct sockaddr __user *, usockaddr,
		int __user *, usockaddr_len)
{
	BUG();
}

SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, addr, int, addr_len)
{
	BUG();
}

SYSCALL_DEFINE2(listen, int, fd, int, backlog)
{
	BUG();
}

SYSCALL_DEFINE4(accept4, int, fd, struct sockaddr __user *, upeer_sockaddr,
		int __user *, upeer_addrlen, int, flags)
{
	BUG();
}

SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr,
		int __user *, upeer_addrlen)
{
	BUG();
}

SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
		unsigned int, flags, struct sockaddr __user *, addr,
		int, addr_len)
{
	BUG();
}

SYSCALL_DEFINE4(send, int, fd, void __user *, buff, size_t, len,
		unsigned int, flags)
{
	BUG();
}

SYSCALL_DEFINE3(sendmsg, int, fd, struct user_msghdr __user *, msg,
		unsigned int, flags)
{
	BUG();
}

SYSCALL_DEFINE6(recvfrom, int, fd, void __user *, ubuf, size_t, size,
		unsigned int, flags, struct sockaddr __user *, addr,
		int __user *, uaddr_len)
{
	BUG();
}

SYSCALL_DEFINE4(recv, int, fd, void __user *, buff, size_t, len,
		unsigned int, flags)
{
	BUG();
}

SYSCALL_DEFINE3(recvmsg, int, fd, struct user_msghdr __user *, msg,
		unsigned int, flags)
{
	BUG();
}

SYSCALL_DEFINE2(shutdown, int, fd, int, how)
{
	BUG();
}

asmlinkage long sys_poll(struct pollfd __user *ufds, unsigned int nfds,
			long timeout_msecs)
{
	BUG();
}
#endif /* Socket SYSCALL */

#ifndef CONFIG_EPOLL
SYSCALL_DEFINE1(epoll_create1, int, flags)
{
	BUG();
}

SYSCALL_DEFINE1(epoll_create, int, size)
{
	BUG();
}

SYSCALL_DEFINE4(epoll_ctl, int, epfd, int, op, int, fd,
		struct epoll_event __user *, event)
{
	BUG();
}

SYSCALL_DEFINE4(epoll_wait, int, epfd, struct epoll_event __user *, events,
		int, maxevents, int, timeout)
{
	BUG();
}
#endif /* CONFIG_EPOLL */
