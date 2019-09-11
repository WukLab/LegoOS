/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/sched.h>
#include <lego/cpumask.h>
#include <lego/sched.h>
#include <lego/sched_rt.h>
#include <lego/signal.h>
#include <lego/comp_common.h>
#include <processor/processor.h>

#if 0
#define INIT_SCHED_POLICY						\
	.prio		= MAX_PRIO-20,					\
	.static_prio	= MAX_PRIO-20,					\
	.normal_prio	= MAX_PRIO-20,					\
	.policy		= SCHED_NORMAL,
#else
#define INIT_SCHED_POLICY						\
	.prio		= 0,						\
	.static_prio	= 0,						\
	.normal_prio	= 0,						\
	.policy		= SCHED_RR,
#endif

/*
 * boot-time rlimit defaults for the init task:
 */
#define INIT_RLIMITS							\
{									\
	[RLIMIT_CPU]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_FSIZE]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_DATA]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_STACK]		= {       _STK_LIM,  RLIM_INFINITY },	\
	[RLIMIT_CORE]		= {              0,  RLIM_INFINITY },	\
	[RLIMIT_RSS]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_NPROC]		= {              0,              0 },	\
	[RLIMIT_NOFILE]		= {   INR_OPEN_CUR,   INR_OPEN_MAX },	\
	[RLIMIT_MEMLOCK]	= {    MLOCK_LIMIT,    MLOCK_LIMIT },	\
	[RLIMIT_AS]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_LOCKS]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
	[RLIMIT_SIGPENDING]	= { 		0,	       0 },	\
	[RLIMIT_MSGQUEUE]	= {   MQ_BYTES_MAX,   MQ_BYTES_MAX },	\
	[RLIMIT_NICE]		= { 0, 0 },				\
	[RLIMIT_RTPRIO]		= { 0, 0 },				\
	[RLIMIT_RTTIME]		= {  RLIM_INFINITY,  RLIM_INFINITY },	\
}

#define INIT_SIGNALS(sig) {						\
	.nr_threads	= 1,						\
	.thread_head	= LIST_HEAD_INIT(init_task.thread_node),	\
	.wait_chldexit	= __WAIT_QUEUE_HEAD_INITIALIZER(sig.wait_chldexit),\
	.shared_pending	= { 						\
		.list = LIST_HEAD_INIT(sig.shared_pending.list),	\
		.signal =  {{0}}},					\
	.posix_timers	 = LIST_HEAD_INIT(sig.posix_timers),		\
	.rlim		= INIT_RLIMITS,					\
}

#define INIT_SIGHAND(sighand) {						\
	.count		= ATOMIC_INIT(1), 				\
	.action		= { { { .sa_handler = SIG_DFL, } }, },		\
	.siglock	= __SPIN_LOCK_UNLOCKED(sighand.siglock),	\
	.signalfd_wqh	= __WAIT_QUEUE_HEAD_INITIALIZER(sighand.signalfd_wqh),	\
}

#define INIT_TASK(tsk)							\
{									\
	.state		= 0,						\
	.stack		= &init_thread_info,				\
	.usage		= ATOMIC_INIT(2),				\
	.comm		= "swapper",					\
	.flags		= PF_KTHREAD,					\
	INIT_SCHED_POLICY						\
	.cpus_allowed	= CPU_MASK_ALL,					\
	.nr_cpus_allowed= NR_CPUS,					\
	.mm		= &init_mm,					\
	.active_mm	= &init_mm,					\
	.rt		= {						\
		.run_list	= LIST_HEAD_INIT(tsk.rt.run_list),	\
		.time_slice	= RR_TIMESLICE,				\
	},								\
	.tasks		= LIST_HEAD_INIT(tsk.tasks),			\
	.ptraced	= LIST_HEAD_INIT(tsk.ptraced),			\
	.ptrace_entry	= LIST_HEAD_INIT(tsk.ptrace_entry),		\
	.real_parent	= &tsk,						\
	.parent		= &tsk,						\
	.children	= LIST_HEAD_INIT(tsk.children),			\
	.sibling	= LIST_HEAD_INIT(tsk.sibling),			\
	.group_leader	= &tsk,						\
	.files		= &init_files,					\
	.signal		= &init_signals,				\
	.sighand	= &init_sighand,				\
	.pending	= {						\
		.list = LIST_HEAD_INIT(tsk.pending.list),		\
		.signal = {{0}}},					\
	.thread_group	= LIST_HEAD_INIT(tsk.thread_group),		\
	.thread_node	= LIST_HEAD_INIT(init_signals.thread_head),	\
	.alloc_lock	= __SPIN_LOCK_UNLOCKED(tsk.alloc_lock),		\
	.pi_lock	= __SPIN_LOCK_UNLOCKED(tsk.pi_lock),		\
	.real_cred	= &init_cred,					\
	.cred		= &init_cred,					\
	.restart_block = {						\
		.fn = do_no_restart_syscall,				\
	},								\
	.thread		= INIT_THREAD,					\
}

#define GLOBAL_ROOT_UID	1001
#define GLOBAL_ROOT_GID 0

struct cred init_cred = {
	/* both cred and real_cred */
	.usage			= ATOMIC_INIT(2),
	.uid			= GLOBAL_ROOT_UID,
	.gid			= GLOBAL_ROOT_GID,
	.suid			= GLOBAL_ROOT_UID,
	.sgid			= GLOBAL_ROOT_GID,
	.euid			= GLOBAL_ROOT_UID,
	.egid			= GLOBAL_ROOT_GID,
	.fsuid			= GLOBAL_ROOT_UID,
	.fsgid			= GLOBAL_ROOT_GID,
};

static struct files_struct init_files = {
	.count		= ATOMIC_INIT(1),
	.file_lock	= __SPIN_LOCK_UNLOCKED(init_files.file_lock),
};

static struct signal_struct init_signals = INIT_SIGNALS(init_signals);
static struct sighand_struct init_sighand = INIT_SIGHAND(init_sighand);

#ifdef CONFIG_COMP_PROCESSOR
static struct processor_manager	init_pm_data = {
	.home_node		= UNSET_HOME_NODE,
	.replica_node		= UNSET_REPLICA_NODE,
#ifdef CONFIG_GSM
	.pgcache_node		= UNSET_PGCACHE_NODE,
	.storage_node		= UNSET_STORAGE_NODE,
#endif
#ifdef CONFIG_CHECKPOINT
	.process_barrier	= ATOMIC_INIT(0),
#endif
};
#endif

struct task_struct init_task = INIT_TASK(init_task);

/*
 * Initial task kernel stack.
 * The alignment is handled specially by linker script.
 */
union thread_union init_thread_union __init_task_data = {
	INIT_THREAD_INFO(init_task)
};

void __init patch_init_task(void)
{
#ifdef CONFIG_COMP_PROCESSOR
	init_task.pm_data = init_pm_data;
#endif
}
