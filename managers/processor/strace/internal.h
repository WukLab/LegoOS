/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _MANAGER_PROCESSOR_STRACE_INTERNAL_H_
#define _MANAGER_PROCESSOR_STRACE_INTERNAL_H_

#include <lego/strace.h>
#include <lego/kernel.h>
#include <lego/kconfig.h>
#include <generated/unistd_64.h>

/* per syscall information */
struct strace_syscall_info {
	atomic_t	nr_called;
	atomic_t	nr_errors;

	/*
	 * Cached syscall enter time.
	 * This is per-thread, we are safe here.
	 */
	unsigned long	time_enter_ns;

	/*
	 * Total syscall execution time of this syscall
	 * invoked within this thread.
	 */
	unsigned long	time_ns;

	/*
	 * Save the syscall number in the struct
	 * because we need to sort the whole array.
	 */
	unsigned long	syscall_nr;
};

/* per process strace information */
struct strace_info {
	struct strace_syscall_info	info[NR_syscalls];

	/*
	 * We only enqueue to thread group leader's strace info.
	 * We use task_lock(leader) to serialize enqueue.
	 *
	 * But we don't do dequeue when thread exit. We do the
	 * batch free while the group dead.
	 */
	struct list_head		next;
};

static inline struct strace_info *current_strace_info(void)
{
	return current->private_strace;
}

static inline struct strace_info *get_task_strace_info(struct task_struct *p)
{
	return p->private_strace;
}

static inline void set_task_strace_info(struct task_struct *p,
					struct strace_info *si)
{
	p->private_strace = si;
}

static inline void clear_task_strace_info(struct task_struct *p)
{
	p->private_strace = NULL;
}

/* Helpers */
struct strace_flag {
	unsigned long	val;
	const char	*str;
};
void strace_printflags(struct strace_flag *sf, unsigned long flags, unsigned char *buf);

#define SF(val)		{ (unsigned long)val, #val }
#define SEND		{ 0, NULL }

enum strace_actions {
	STRACE_ENTER,
	STRACE_LEAVE,
};

#define sp(fmt, ...)							\
do {									\
	if (IS_ENABLED(CONFIG_STRACE_PRINT_ON_ENTER) &&			\
	    syscall_action == STRACE_ENTER)				\
		pr_info("CPU%d PID%d-%s %s(" fmt ")\n",			\
			smp_processor_id(), current->pid,		\
			current->comm, __func__,			\
			__VA_ARGS__);					\
									\
	if (IS_ENABLED(CONFIG_STRACE_PRINT_ON_LEAVE) &&			\
	    syscall_action == STRACE_LEAVE)				\
		pr_info("CPU%d PID%d-%s %s(" fmt ") = %d, %#lx\n",	\
			smp_processor_id(), current->pid,		\
			current->comm, __func__,			\
			__VA_ARGS__, (int)syscall_ret, syscall_ret);	\
} while (0)

#define __sp(fmt, ...)							\
do {									\
	if (IS_ENABLED(CONFIG_STRACE_PRINT_ON_ENTER) &&			\
	    syscall_action == STRACE_ENTER)				\
		pr_info("CPU%d PID%d-%s " fmt "\n",			\
			smp_processor_id(), current->pid,		\
			current->comm,					\
			__VA_ARGS__);					\
									\
	if (IS_ENABLED(CONFIG_STRACE_PRINT_ON_LEAVE) &&			\
	    syscall_action == STRACE_LEAVE)				\
		pr_info("CPU%d PID%d-%s " fmt " = %d, %#lx\n",		\
			smp_processor_id(), current->pid,		\
			current->comm,					\
			__VA_ARGS__, (int)syscall_ret, syscall_ret);	\
} while (0)

/*
 * arguments:
 * syscall_nr, STRACE_ENTER/LEAVE,
 * syscall_ret
 * arg1, arg2,
 * arg3, arg4,
 * arg5, arg6,
 */
typedef void (*strace_call_ptr_t)(unsigned long, unsigned long, unsigned long,
				  unsigned long, unsigned long,
				  unsigned long, unsigned long,
				  unsigned long, unsigned long);

#define STRACE_DEFINE0(sname)					\
	void strace__##sname(unsigned long syscall_nr,		\
			     unsigned long syscall_action,	\
			     unsigned long syscall_ret)

#define STRACE_DEFINE1(name, ...) STRACE_DEFINEx(1, __##name, __VA_ARGS__)
#define STRACE_DEFINE2(name, ...) STRACE_DEFINEx(2, __##name, __VA_ARGS__)
#define STRACE_DEFINE3(name, ...) STRACE_DEFINEx(3, __##name, __VA_ARGS__)
#define STRACE_DEFINE4(name, ...) STRACE_DEFINEx(4, __##name, __VA_ARGS__)
#define STRACE_DEFINE5(name, ...) STRACE_DEFINEx(5, __##name, __VA_ARGS__)
#define STRACE_DEFINE6(name, ...) STRACE_DEFINEx(6, __##name, __VA_ARGS__)

#define STRACE_DEFINEx(x, sname, ...)				\
	__STRACE_DEFINEx(x, sname, __VA_ARGS__)

#define __STRACE_DEFINEx(x, name, ...)				\
	void strace##name(unsigned long syscall_nr,		\
			  unsigned long syscall_action,		\
			  unsigned long syscall_ret,		\
			  __MAP(x,__SC_DECL,__VA_ARGS__))

STRACE_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,
		 int __user *, parent_tidptr,
		 int __user *, child_tidptr,
		 unsigned long, tls);

STRACE_DEFINE5(waitid, int, which, pid_t, upid, struct siginfo __user *, infop,
	       int, options, struct rusage __user *, ru);


STRACE_DEFINE4(wait4, pid_t, upid, int __user *, stat_addr,
	       int, options, struct rusage __user *, ru);

STRACE_DEFINE0(fork);
STRACE_DEFINE0(getpid);
STRACE_DEFINE1(set_tid_address, int __user *, tidptr);

STRACE_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
	       unsigned long, prot, unsigned long, flags,
	       unsigned long, fd, unsigned long, off);

STRACE_DEFINE2(munmap, unsigned long, addr, size_t, len);

STRACE_DEFINE3(mprotect, unsigned long, start, size_t, len,
	       unsigned long, prot);

STRACE_DEFINE1(pipe, int __user *, flides);
STRACE_DEFINE2(pipe2, int __user *, flides, int, flags);

STRACE_DEFINE1(dup, unsigned int, fildes);
STRACE_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd);

#endif /* _MANAGER_PROCESSOR_STRACE_INTERNAL_H_ */
