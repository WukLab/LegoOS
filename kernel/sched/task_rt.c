/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Real-Time Scheduling Class
 * Mapped to SCHED_FIFO and SCHED_RR policies
 */

#include <lego/sched.h>
#include "sched.h"

/*
 * Adding/removing a task to/from a priority array:
 */
static void
enqueue_task_rt(struct rq *rq, struct task_struct *p, int flags)
{
}

static void
dequeue_task_rt(struct rq *rq, struct task_struct *p, int flags)
{
}

static void put_prev_task_rt(struct rq *rq, struct task_struct *p)
{
}

static struct task_struct *
pick_next_task_rt(struct rq *rq, struct task_struct *prev)
{
	return NULL;
}

const struct sched_class rt_sched_class = {
	.next			= &fair_sched_class,
	.enqueue_task		= enqueue_task_rt,
	.dequeue_task		= dequeue_task_rt,

	.pick_next_task		= pick_next_task_rt,
	.put_prev_task		= put_prev_task_rt,
};
