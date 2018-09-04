/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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

#include <lego/smp.h>
#include <lego/sched.h>
#include <lego/sched_rt.h>
#include "sched.h"

/* Timeslice a real-time round-robin task can run */
int sysctl_sched_rr_timeslice = RR_TIMESLICE;

static inline struct task_struct *rt_task_of(struct sched_rt_entity *rt_se)
{
	return container_of(rt_se, struct task_struct, rt);
}

static inline struct rq *rq_of_rt_rq(struct rt_rq *rt_rq)
{
	return container_of(rt_rq, struct rq, rt);
}

static inline struct rq *rq_of_rt_se(struct sched_rt_entity *rt_se)
{
	struct task_struct *p = rt_task_of(rt_se);

	return task_rq(p);
}

static inline struct rt_rq *rt_rq_of_se(struct sched_rt_entity *rt_se)
{
	struct rq *rq = rq_of_rt_se(rt_se);

	return &rq->rt;
}

static inline int on_rt_rq(struct sched_rt_entity *rt_se)
{
	return !list_empty(&rt_se->run_list);
}

static inline u64 sched_rt_runtime(struct rt_rq *rt_rq)
{
	return rt_rq->rt_runtime;
}

static inline int rt_se_prio(struct sched_rt_entity *rt_se)
{
	return rt_task_of(rt_se)->prio;
}

/*
 * Update the current task's runtime statistics. Skip current tasks that
 * are not in our scheduling class.
 */
static void update_curr_rt(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	u64 delta_exec;

	if (curr->sched_class != &rt_sched_class)
		return;

	delta_exec = rq_clock_task(rq) - curr->se.exec_start;
	if (unlikely((s64)delta_exec <= 0))
		return;

	curr->se.sum_exec_runtime += delta_exec;
	curr->se.exec_start = rq_clock_task(rq);
}

/*
 * Put task to the head or the end of the run list without the overhead of
 * dequeue followed by enqueue.
 */
static void
requeue_rt_entity(struct rt_rq *rt_rq, struct sched_rt_entity *rt_se, int head)
{
	if (on_rt_rq(rt_se)) {
		struct rt_prio_array *array = &rt_rq->active;
		struct list_head *queue = array->queue + rt_se_prio(rt_se);

		if (head)
			list_move(&rt_se->run_list, queue);
		else
			list_move_tail(&rt_se->run_list, queue);
	}
}

static void yield_task_rt(struct rq *rq)
{
	struct sched_rt_entity *rt_se = &rq->curr->rt;
	struct rt_rq *rt_rq = &rq->rt;

	requeue_rt_entity(rt_rq, rt_se, 0);
}

static inline
void inc_rt_tasks(struct sched_rt_entity *rt_se, struct rt_rq *rt_rq)
{
	int prio = rt_se_prio(rt_se);

	WARN_ON(!rt_prio(prio));
	rt_rq->rt_nr_running += 1;
}

static inline
void dec_rt_tasks(struct sched_rt_entity *rt_se, struct rt_rq *rt_rq)
{
	int prio = rt_se_prio(rt_se);

	WARN_ON(!rt_prio(prio));
	WARN_ON(!rt_rq->rt_nr_running);
	rt_rq->rt_nr_running -= 1;
}

static inline void __dequeue_rt_entity(struct sched_rt_entity *rt_se)
{
	struct rt_rq *rt_rq = rt_rq_of_se(rt_se);
	struct rt_prio_array *array = &rt_rq->active;

	list_del_init(&rt_se->run_list);
	if (list_empty(array->queue + rt_se_prio(rt_se)))
		__clear_bit(rt_se_prio(rt_se), array->bitmap);

	dec_rt_tasks(rt_se, rt_rq);
}

static inline void __enqueue_rt_entity(struct sched_rt_entity *rt_se, bool head)
{
	struct rt_rq *rt_rq = rt_rq_of_se(rt_se);
	struct rt_prio_array *array = &rt_rq->active;
	struct list_head *queue = array->queue + rt_se_prio(rt_se);

	if (head)
		list_add(&rt_se->run_list, queue);
	else
		list_add_tail(&rt_se->run_list, queue);
	__set_bit(rt_se_prio(rt_se), array->bitmap);

	inc_rt_tasks(rt_se, rt_rq);
}

static void enqueue_rt_entity(struct sched_rt_entity *rt_se, bool head)
{
	struct rq *rq = rq_of_rt_se(rt_se);
	struct rt_rq *rt_rq = rt_rq_of_se(rt_se);

	if (rt_rq->rt_queued) {
		BUG_ON(!rq->nr_running);
		sub_nr_running(rq, rt_rq->rt_nr_running);
		rt_rq->rt_queued = 0;
	}

	if (on_rt_rq(rt_se))
		__dequeue_rt_entity(rt_se);

	__enqueue_rt_entity(rt_se, head);

	if (!rt_rq->rt_queued && rt_rq->rt_nr_running) {
		add_nr_running(rq, rt_rq->rt_nr_running);
		rt_rq->rt_queued = 1;
	}
}

static void dequeue_rt_entity(struct sched_rt_entity *rt_se)
{
	struct rq *rq = rq_of_rt_se(rt_se);
	struct rt_rq *rt_rq = rt_rq_of_se(rt_se);

	if (rt_rq->rt_queued) {
		BUG_ON(!rq->nr_running);
		sub_nr_running(rq, rt_rq->rt_nr_running);
		rt_rq->rt_queued = 0;
	}

	if (on_rt_rq(rt_se))
		__dequeue_rt_entity(rt_se);

	if (!rt_rq->rt_queued && rt_rq->rt_nr_running) {
		add_nr_running(rq, rt_rq->rt_nr_running);
		rt_rq->rt_queued = 1;
	}
}

/*
 * Adding/removing a task to/from a priority array:
 */
static void
enqueue_task_rt(struct rq *rq, struct task_struct *p, int flags)
{
	struct sched_rt_entity *rt_se = &p->rt;

	if (flags & ENQUEUE_WAKEUP)
		rt_se->timeout = 0;

	enqueue_rt_entity(rt_se, flags & ENQUEUE_HEAD);
}

static void
dequeue_task_rt(struct rq *rq, struct task_struct *p, int flags)
{
	struct sched_rt_entity *rt_se = &p->rt;

	update_curr_rt(rq);
	dequeue_rt_entity(rt_se);
}

static void put_prev_task_rt(struct rq *rq, struct task_struct *p)
{
	update_curr_rt(rq);
}

/*
 * Preempt the current task with a newly woken task if needed:
 * (invoked during wake up a new task)
 */
static void check_preempt_curr_rt(struct rq *rq, struct task_struct *p, int flags)
{
	if (p->prio < rq->curr->prio) {
		resched_curr(rq);
		return;
	}
}

static struct sched_rt_entity *
pick_next_rt_entity(struct rq *rq, struct rt_rq *rt_rq)
{
	struct rt_prio_array *array = &rt_rq->active;
	struct sched_rt_entity *next = NULL;
	struct list_head *queue;
	int idx;

	idx = sched_find_first_bit(array->bitmap);
	BUG_ON(idx >= MAX_RT_PRIO);

	queue = array->queue + idx;
	next = list_entry(queue->next, struct sched_rt_entity, run_list);

	return next;
}

static struct task_struct *
pick_next_task_rt(struct rq *rq, struct task_struct *prev)
{
	struct sched_rt_entity *rt_se;
	struct task_struct *p;
	struct rt_rq *rt_rq = &rq->rt;

	if (!rt_rq->rt_queued)
		return NULL;

	put_prev_task(rq, prev);

	rt_se = pick_next_rt_entity(rq, rt_rq);
	BUG_ON(!rt_se);

	p = rt_task_of(rt_se);
	p->se.exec_start = rq_clock_task(rq);

	return p;
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

/*
 * Priority of the task has changed. This may cause
 * us to initiate a push or pull.
 */
static void
prio_changed_rt(struct rq *rq, struct task_struct *p, int oldprio)
{
	if (!task_on_rq_queued(p))
		return;

	if (rq->curr == p) {
		/* Simply resched on drop of prio */
		if (oldprio < p->prio)
			resched_curr(rq);
	} else {
		/*
		 * This task is not running, but if it is
		 * greater than the current running task
		 * then reschedule.
		 */
		if (p->prio < rq->curr->prio)
			resched_curr(rq);
	}
}

static void set_curr_task_rt(struct rq *rq)
{
	struct task_struct *p = rq->curr;

	p->se.exec_start = rq_clock_task(rq);
}

static unsigned int get_rr_interval_rt(struct rq *rq, struct task_struct *task)
{
	/*
	 * Time slice is 0 for SCHED_FIFO tasks
	 */
	if (task->policy == SCHED_RR)
		return sysctl_sched_rr_timeslice;
	else
		return 0;
}

/*
 * When switching a task to RT, we may overload the runqueue
 * with RT tasks. In this case we try to push them off to
 * other runqueues.
 */
static void switched_to_rt(struct rq *rq, struct task_struct *p)
{
	/*
	 * If we are already running, then there's nothing
	 * that needs to be done. But if we are not running
	 * we may need to preempt the current running task.
	 * If that current running task is also an RT task
	 * then see if we can move to another run queue.
	 */
	if (task_on_rq_queued(p) && rq->curr != p) {
		if (p->prio < rq->curr->prio)
			resched_curr(rq);
	}
}

static void task_tick_rt(struct rq *rq, struct task_struct *p, int queued)
{
	struct sched_rt_entity *rt_se = &p->rt;
	struct rt_rq *rt_rq = rt_rq_of_se(rt_se);

	update_curr_rt(rq);

	/*
	 * RR tasks need a special form of timeslice management.
	 * FIFO tasks have no timeslices.
	 */
	if (p->policy != SCHED_RR)
		return;

	if (--p->rt.time_slice)
		return;

	p->rt.time_slice = sysctl_sched_rr_timeslice;

	if (rt_se->run_list.prev != rt_se->run_list.next) {
		requeue_rt_entity(rt_rq, rt_se, 0);
		resched_curr(rq);
		return;
	}
}

#ifdef CONFIG_SMP
atomic_t nr_pick;
static int find_next_rr_cpu(struct task_struct *p, int old_cpu)
{
	return atomic_fetch_add(1, &nr_pick) % nr_cpus;
}

static int
select_task_rq_rt(struct task_struct *p, int cpu, int sd_flag, int wake_flags)
{
	int new_cpu = cpu;

	/* Only fork time? */
	if (sd_flag == SD_BALANCE_FORK) {
retry:
		new_cpu = find_next_rr_cpu(p, cpu);
		if (unlikely(!cpu_active(new_cpu)))
			goto retry;
	}
	return new_cpu;
}
#endif

const struct sched_class rt_sched_class = {
	.next			= &fair_sched_class,
	.enqueue_task		= enqueue_task_rt,
	.dequeue_task		= dequeue_task_rt,
	.yield_task		= yield_task_rt,

	.check_preempt_curr	= check_preempt_curr_rt,

	.pick_next_task		= pick_next_task_rt,
	.put_prev_task		= put_prev_task_rt,

#ifdef CONFIG_SMP
	.select_task_rq		= select_task_rq_rt,
	.set_cpus_allowed	= set_cpus_allowed_common,
#endif

	.set_curr_task		= set_curr_task_rt,
	.task_tick		= task_tick_rt,

	.get_rr_interval	= get_rr_interval_rt,
	.prio_changed		= prio_changed_rt,
	.switched_to		= switched_to_rt,

	.update_curr		= update_curr_rt,
};
