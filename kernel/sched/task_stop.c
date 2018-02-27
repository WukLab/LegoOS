/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Stop-task scheduling class.
 * The stop task is the highest priority task in the system,
 * it preempts everything and will be preempted by nothing.
 */

#include <lego/sched.h>
#include "sched.h"

#ifdef CONFIG_SMP
static int
select_task_rq_stop(struct task_struct *p, int cpu, int sd_flag, int flags)
{
	return task_cpu(p); /* stop tasks as never migrate */
}
#endif /* CONFIG_SMP */

static void
enqueue_task_stop(struct rq *rq, struct task_struct *p, int flags)
{
	add_nr_running(rq, 1);
}

static void
dequeue_task_stop(struct rq *rq, struct task_struct *p, int flags)
{
	sub_nr_running(rq, 1);
}

static void yield_task_stop(struct rq *rq)
{
	BUG(); /* the stop task should never yield, its pointless. */
}

static struct task_struct *
pick_next_task_stop(struct rq *rq, struct task_struct *prev)
{
	struct task_struct *stop = rq->stop;

	if (!stop || !task_on_rq_queued(stop))
		return NULL;

	put_prev_task(rq, prev);

	stop->se.exec_start = rq_clock_task(rq);

	return stop;
}

static void put_prev_task_stop(struct rq *rq, struct task_struct *prev)
{
	struct task_struct *curr = rq->curr;
	u64 delta_exec;

	delta_exec = rq_clock_task(rq) - curr->se.exec_start;
	if (unlikely((s64)delta_exec < 0))
		delta_exec = 0;

	curr->se.sum_exec_runtime += delta_exec;
	curr->se.exec_start = rq_clock_task(rq);
}

static void
task_tick_stop(struct rq *rq, struct task_struct *curr, int queued)
{

}

static void set_curr_task_stop(struct rq *rq)
{
	struct task_struct *stop = rq->stop;

	stop->se.exec_start = rq_clock_task(rq);
}

static unsigned int
get_rr_interval_stop(struct rq *rq, struct task_struct *task)
{
	return 0;
}

static void
prio_changed_stop(struct rq *rq, struct task_struct *p, int oldprio)
{
	BUG(); /* how?!, what priority? */
}

static void switched_to_stop(struct rq *rq, struct task_struct *p)
{
	BUG(); /* its impossible to change to this class */
}

static void update_curr_stop(struct rq *rq)
{

}

const struct sched_class stop_sched_class = {
	.next			= &rt_sched_class,

	.enqueue_task		= enqueue_task_stop,
	.dequeue_task		= dequeue_task_stop,
	.yield_task		= yield_task_stop,

	.pick_next_task		= pick_next_task_stop,
	.put_prev_task		= put_prev_task_stop,

#ifdef CONFIG_SMP
	.select_task_rq		= select_task_rq_stop,
	.set_cpus_allowed	= set_cpus_allowed_common,
#endif

	.set_curr_task		= set_curr_task_stop,
	.task_tick		= task_tick_stop,

	.get_rr_interval	= get_rr_interval_stop,

	.prio_changed		= prio_changed_stop,
	.switched_to		= switched_to_stop,
	.update_curr		= update_curr_stop,
};
