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

void init_rt_rq(struct rt_rq *rt_rq)
{
	struct rt_prio_array *array;
	int i;

	array = &rt_rq->active;
	for (i = 0; i < MAX_RT_PRIO; i++) {
		INIT_LIST_HEAD(array->queue + i);
		__clear_bit(i, array->bitmap);
	}
	/* delimiter for bitsearch */
	__set_bit(MAX_RT_PRIO, array->bitmap);

	/* We start is dequeued state, because no RT tasks are queued */
	rt_rq->rt_queued = 0;

	rt_rq->rt_time = 0;
	rt_rq->rt_throttled = 0;
	rt_rq->rt_runtime = 0;
	spin_lock_init(&rt_rq->rt_runtime_lock);
}

const struct sched_class rt_sched_class = {
	.next			= &fair_sched_class,
	.enqueue_task		= enqueue_task_rt,
	.dequeue_task		= dequeue_task_rt,

	.pick_next_task		= pick_next_task_rt,
	.put_prev_task		= put_prev_task_rt,
};
