/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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

#define INIT_TASK(tsk)							\
{									\
	.state		= 0,						\
	.comm		= "swapper",					\
	.flags		= PF_KTHREAD,					\
	INIT_SCHED_POLICY						\
	.cpus_allowed	= CPU_MASK_ALL,					\
	.nr_cpus_allowed= NR_CPUS,					\
	.mm		= &init_mm,					\
	.active_mm	= &init_mm,					\
	.stack		= &init_thread_info,				\
	.thread		= INIT_THREAD,					\
	.rt		= {						\
		.run_list	= LIST_HEAD_INIT(tsk.rt.run_list),	\
		.time_slice	= RR_TIMESLICE,				\
	},								\
	.tasks		= LIST_HEAD_INIT(tsk.tasks),			\
	.real_parent	= &tsk,						\
	.parent		= &tsk,						\
	.children	= LIST_HEAD_INIT(tsk.children),			\
	.sibling	= LIST_HEAD_INIT(tsk.sibling),			\
}

struct task_struct init_task = INIT_TASK(init_task);

/*
 * Initial task kernel stack.
 * The alignment is handled specially by linker script.
 */
union thread_union init_thread_union __init_task_data = {
	INIT_THREAD_INFO(init_task)
};
