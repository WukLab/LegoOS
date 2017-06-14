/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include "sched.h"

static void
enqueue_task_fair(struct rq *rq, struct task_struct *p, int flags)
{
}

static void
dequeue_task_fair(struct rq *rq, struct task_struct *p, int flags)
{
}

static void put_prev_task_fair(struct rq *rq, struct task_struct *p)
{
}

static struct task_struct *
pick_next_task_fair(struct rq *rq, struct task_struct *prev)
{
	return NULL;
}

void init_cfs_rq(struct cfs_rq *cfs_rq)
{
	cfs_rq->tasks_timeline = RB_ROOT;
	cfs_rq->min_vruntime = (u64)(-(1LL << 20));
}

const struct sched_class fair_sched_class = {
	.next			= &idle_sched_class,

	.enqueue_task		= enqueue_task_fair,
	.dequeue_task		= dequeue_task_fair,

	.pick_next_task		= pick_next_task_fair,
	.put_prev_task		= put_prev_task_fair,
};
