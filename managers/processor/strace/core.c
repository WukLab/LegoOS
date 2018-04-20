/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/smp.h>
#include <lego/mmap.h>
#include <lego/ptrace.h>
#include <lego/strace.h>
#include <lego/sched.h>
#include <lego/syscalls.h>
#include <lego/waitpid.h>
#include <lego/files.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <processor/fs.h>
#include <generated/asm-offsets.h>
#include <generated/unistd_64.h>

#include "internal.h"

void strace_enter_default(unsigned long syscall_nr, unsigned long syscall_action,
			  unsigned long syscall_ret,
			  unsigned long a1, unsigned long a2,
			  unsigned long a3, unsigned long a4,
			  unsigned long a5, unsigned long a6)
{
	__sp("%pf", sys_call_table[syscall_nr]);
}

/*
 * The syscall tracer table
 * We really can not figure out a way to fill this automatically?
 */
const strace_call_ptr_t strace_call_table[__NR_syscall_max+1] = {
	[0 ... __NR_syscall_max]	= &strace_enter_default,

	[__NR_clone]			= (strace_call_ptr_t)&strace__clone,
	[__NR_fork]			= (strace_call_ptr_t)&strace__fork,
	[__NR_set_tid_address]		= (strace_call_ptr_t)&strace__set_tid_address,
	[__NR_wait4]			= (strace_call_ptr_t)&strace__wait4,
	[__NR_waitid]			= (strace_call_ptr_t)&strace__waitid,
	[__NR_mmap]			= (strace_call_ptr_t)&strace__mmap,
	[__NR_munmap]			= (strace_call_ptr_t)&strace__munmap,
	[__NR_mprotect]			= (strace_call_ptr_t)&strace__mprotect,
	[__NR_pipe2]			= (strace_call_ptr_t)&strace__pipe2,
	[__NR_pipe]			= (strace_call_ptr_t)&strace__pipe,
	[__NR_dup2]			= (strace_call_ptr_t)&strace__dup2,
	[__NR_dup]			= (strace_call_ptr_t)&strace__dup,
};

/*
 * Modify this table if you want to trace specific syscalls.
 */
#ifdef CONFIG_STRACE_PRINT_ON_SPECIFIC
static bool strace_printable_nr[__NR_syscall_max+1] = {
	[0 ... __NR_syscall_max]	= false,

	/* threads group */
	[__NR_fork]			= true,
	[__NR_vfork]			= true,
	[__NR_clone]			= true,
	[__NR_execve]			= true,

	/* mm group */
	[__NR_mmap]			= true,
	[__NR_mprotect]			= true,
	//[__NR_munmap]			= true,

	[__NR_dup]			= true,
	[__NR_dup2]			= true,
	[__NR_pipe]			= true,
	[__NR_pipe2]			= true,
	[__NR_fcntl]			= true,
};
#endif

static inline bool printable(unsigned long nr)
{
#ifdef CONFIG_STRACE_PRINT_ON_SPECIFIC
	return strace_printable_nr[nr];
#else
	return true;
#endif
}

static inline void inc_strace_event(unsigned long nr, unsigned long ret)
{
	struct strace_info *si;
	struct strace_syscall_info *ssi;

	si = current_strace_info();
	BUG_ON(!si);
	ssi = &si->info[nr];

	atomic_inc(&ssi->nr_called);

	/*
	 * This simple checking should work for
	 * all syscalls. Do remember to cast it
	 * to long, instead of int.
	 */
	if (unlikely((long)ret < 0))
		atomic_inc(&ssi->nr_errors);
}

static inline void __strace_syscall_exit(unsigned long nr, unsigned long ret)
{
	struct strace_info *si;
	struct strace_syscall_info *ssi;
	unsigned long diff, time_leave_ns = sched_clock();

	si = current_strace_info();
	ssi = &si->info[nr];

	diff = time_leave_ns - ssi->time_enter_ns;
	if (unlikely(diff > time_leave_ns)) {
		WARN_ON_ONCE(1);
		goto out;
	}

	ssi->time_ns += diff;
out:
	inc_strace_event(nr, ret);
}

static inline void __strace_syscall_enter(unsigned long nr)
{
	struct strace_info *si;
	struct strace_syscall_info *ssi;

	si = current_strace_info();
	ssi = &si->info[nr];
	ssi->time_enter_ns = sched_clock();
}

/*
 * Called before a syscall is invoked
 */
void strace_syscall_enter(struct pt_regs *regs)
{
	unsigned long nr = regs->orig_ax;
	unsigned long a1 = regs->di;
	unsigned long a2 = regs->si;
	unsigned long a3 = regs->dx;
	unsigned long a4 = regs->r10;
	unsigned long a5 = regs->r8;
	unsigned long a6 = regs->r9;

	if (unlikely(nr >= NR_syscalls))
		return;

	if (printable(nr))
		strace_call_table[nr](nr, STRACE_ENTER, 0,
				      a1, a2, a3, a4, a5, a6);
	__strace_syscall_enter(nr);
}

/*
 * Called after a syscall has finished
 */
void strace_syscall_exit(struct pt_regs *regs)
{
	unsigned long syscall_ret = regs->ax;
	unsigned long nr = regs->orig_ax;
	unsigned long a1 = regs->di;
	unsigned long a2 = regs->si;
	unsigned long a3 = regs->dx;
	unsigned long a4 = regs->r10;
	unsigned long a5 = regs->r8;
	unsigned long a6 = regs->r9;

	if (unlikely(nr >= NR_syscalls))
		return;

	__strace_syscall_exit(nr, syscall_ret);

	if (printable(nr))
		strace_call_table[nr](nr, STRACE_LEAVE, syscall_ret,
				      a1, a2, a3, a4, a5, a6);
}

static int strace_compare_time(const void *a, const void *b)
{
	const struct strace_syscall_info *sa = a, *sb = b;

	if (sa->time_ns < sb->time_ns)
		return 1;
	return -1;
}

static inline void sort_strace_by_time(struct strace_info *si)
{
	sort(&si->info, NR_syscalls, sizeof(struct strace_syscall_info),
		strace_compare_time, NULL);
}

void print_strace_info(struct strace_info *si)
{
	int i, nr_total_called = 0, nr_total_errors = 0;
	struct strace_syscall_info *ssi;
	unsigned long total_time_ns, time_ns, per_call_ns;
	u64 p_i, p_re;
	struct timespec ts;

	sort_strace_by_time(si);

	/* Get total runtime first */
	total_time_ns = 0;
	for (i = 0; i < NR_syscalls; i++) {
		ssi = &si->info[i];
		if (!atomic_read(&ssi->nr_called))
			continue;
		total_time_ns += ssi->time_ns;
	}

	pr_info("%% time        seconds  usecs/call     calls    errors syscall\n");
	pr_info("------ -------------- ----------- --------- --------- ----------------\n");
	for (i = 0; i < NR_syscalls; i++) {
		char p_re_buf[8];

		ssi = &si->info[i];
		if (!atomic_read(&ssi->nr_called))
			continue;

		time_ns = ssi->time_ns;

		/* Percentage */
		p_i = div64_u64_rem(time_ns * 100UL, total_time_ns, &p_re);
		scnprintf(p_re_buf, 3, "%Lu", p_re);

		/* Seconds */
		ts = ns_to_timespec(time_ns);

		/* Per-call */
		per_call_ns = time_ns / atomic_read(&ssi->nr_called);

		pr_info("%3Lu.%s %4Ld.%09Ld %11lu %9d %9d %pf\n",
			p_i, p_re_buf,
			(s64)ts.tv_sec, (s64)ts.tv_nsec,
			DIV_ROUND_UP(per_call_ns, 1000UL),
			atomic_read(&ssi->nr_called),
			atomic_read(&ssi->nr_errors),
			sys_call_table[ssi->syscall_nr]);

		nr_total_called += atomic_read(&ssi->nr_called);
		nr_total_errors += atomic_read(&ssi->nr_errors);
	}
	pr_info("------ -------------- ----------- --------- --------- ----------------\n");

	ts = ns_to_timespec(total_time_ns);
	pr_info("%3d.%02d %4Ld.%09Ld             %9d %9d total\n",
		100, 0,
		(s64)ts.tv_sec, (s64)ts.tv_nsec,
		nr_total_called, nr_total_errors);
}

/*
 * Print single task's strace information.
 * You can accumulate before calling.
 */
void print_task_strace_info(struct task_struct *p)
{
	struct strace_info *si;

	si = get_task_strace_info(p);
	if (!si)
		return;

	print_strace_info(si);
}

static void __accumulate_one(struct strace_info *base,
			     struct strace_info *diff)
{
	struct strace_syscall_info *ssi_base, *ssi_diff;
	int i;

	for (i = 0; i < NR_syscalls; i++) {
		ssi_base = &base->info[i];
		ssi_diff = &diff->info[i];

		atomic_add(atomic_read(&ssi_diff->nr_called),
			   &ssi_base->nr_called);
		atomic_add(atomic_read(&ssi_diff->nr_errors),
			   &ssi_base->nr_errors);
		ssi_base->time_ns += ssi_diff->time_ns;
		BUG_ON(ssi_base->syscall_nr != ssi_diff->syscall_nr);
	}
}

/*
 * The good thing about linked list is we really do not need to care if we are
 * the head or not. In fact, everybody can be the head.
 *
 * Even though we add all strace_info of normal threads to their group leader,
 * @p can act as the head now. Besides, this function is called only when
 * the last thread exit, which means group dead. Thus we are safe and the
 * numbers accumulated are accurate.
 */
static int accumulate(struct task_struct *p)
{
	struct strace_info *si_head, *si;
	int nr = 0;

	si_head = get_task_strace_info(p);
	BUG_ON(!si_head);

	if (list_empty(&si_head->next))
		return 0;

	list_for_each_entry(si, &si_head->next, next) {
		__accumulate_one(si_head, si);
		nr++;
	}
	return nr;
}

/*
 * Called when a process group exit().
 * @p is the last live thread within this thread group.
 * We walk through the strace list and accumulate them.
 */
void exit_processor_strace(struct task_struct *p)
{
	struct strace_info *si_head;
	int nr;

	si_head = get_task_strace_info(p);
	if (!si_head)
		return;

	nr = accumulate(p);

	/* myself */
	nr++;

	pr_info("\n");
	pr_info("Kernel strace\n");
	pr_info("Task: %d:%d nr_accumulated_threads: %d\n", p->pid, p->tgid, nr);
	print_strace_info(si_head);
	pr_info("\n");
}

int __fork_processor_strace(struct task_struct *p)
{
	struct task_struct *leader;
	struct strace_info *si_head, *si;
	struct strace_syscall_info *ssi;
	int i;

	si = kzalloc(sizeof(*si), GFP_KERNEL);
	if (!si)
		return -ENOMEM;

	/* init strace_info */
	for (i = 0; i < NR_syscalls; i++) {
		ssi = &si->info[i];
		ssi->syscall_nr = i;
	}
	INIT_LIST_HEAD(&si->next);
	set_task_strace_info(p, si);

	/*
	 * Our design is:
	 * Each thread has its strace info. Threads within a group have
	 * their strace info linked together. And do we enqueue only.
	 * No dequeue happen when a normal thread exit.
	 */
	if (thread_group_leader(p))
		return 0;

	leader = p->group_leader;
	si_head = get_task_strace_info(leader);

	task_lock(leader);
	list_add(&si->next, &si_head->next);
	task_unlock(leader);

	return 0;
}

/*
 * Called during fork() after everything has been setup.
 * Prepare strace buffer for each user thread
 */
int fork_processor_strace(struct task_struct *p)
{
	/* Kernel thread? */
	if (p->flags & PF_KTHREAD) {
		clear_task_strace_info(p);
		return 0;
	}
	return __fork_processor_strace(p);
}
