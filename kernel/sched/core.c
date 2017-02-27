/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/time.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>
#include <lego/spinlock.h>

/*
 * TODO:
 *	Rewrite runqueue
 */

/**
 * sched_clock
 *
 * Scheduler clock - returns current time in nanosec units.
 * This is default implementation.
 * Architectures and sub-architectures can override this.
 */
unsigned long long __weak sched_clock(void)
{
	return (unsigned long long)(jiffies - INITIAL_JIFFIES)
					* (NSEC_PER_SEC / HZ);
}

void user_thread_bug_now(void)
{
	panic("%s\n", __func__);
}

/**
 * schedule_tail - first thing a freshly forked thread must call.
 * @prev: the thread we just switched away from.
 */
asmlinkage __visible void schedule_tail(struct task_struct *prev)
{
	printk("  %s is invoked\n", __func__);
}

static LIST_HEAD(rq_list);
static DEFINE_SPINLOCK(rq_lock);

/*
 * wake_up_new_task - wake up a newly created task for the first time.
 *
 * This function will do some initial scheduler statistics housekeeping
 * that must be done for every newly created context, then puts the task
 * on the runqueue and wakes it.
 */
void wake_up_new_task(struct task_struct *p)
{
	p->on_rq = 1;
	p->state = TASK_RUNNING;

	spin_lock(&rq_lock);
	list_add_tail(&p->run_list, &rq_list);
	spin_unlock(&rq_lock);
}

/*
 * Called from fork()/clone(), to setup a new task to scheduler.
 */
int setup_sched_fork(unsigned long clone_flags, struct task_struct *p)
{
	p->on_rq = 0;
	p->static_prio = 0;
	INIT_LIST_HEAD(&p->run_list);

	/*
	 * We mark the process as NEW here. This guarantees that
	 * nobody will actually run it, and a signal or other external
	 * event cannot wake it up and insert it on the runqueue either.
	 */
	p->state = TASK_NEW;

	return 0;
}

void sched_remove_from_rq(struct task_struct *p)
{
	spin_lock(&rq_lock);
	list_del(&p->run_list);
	spin_unlock(&rq_lock);
}

/**
 * pick_next_task	-	Pick up the highest-prio task:
 *
 * Get next highest-prio task to run from @rq
 * and put the @prev back to @rq
 */
static struct task_struct *pick_next_task( struct task_struct *prev)
{
	struct task_struct *next = NULL;

	spin_lock(&rq_lock);
	if (!list_empty(&rq_list)) {
		struct list_head *list;

		list = rq_list.next;
		list_del(list);
		next = container_of(list, struct task_struct, run_list);

		list_add(&prev->run_list, &rq_list);
	} else
		next = &init_task;
	spin_unlock(&rq_lock);

	return next;
}

static void switch_mm_irqs_off(struct mm_struct *prev,
			       struct mm_struct *next,
			       struct task_struct *tsk)
{
	load_cr3(next->pgd);
}

void schedule(void)
{
	struct task_struct *next, *prev;

	prev = current;
	next = pick_next_task(prev);

	if (likely(prev != next)) {
		switch_mm_irqs_off(prev->mm, next->mm, next);
		switch_to(prev, next, prev);
		barrier();
	}
}

/**
 * try_to_wake_up - wake up a thread
 * @p: the thread to be awakened
 * @state: the mask of task states that can be woken
 * @wake_flags: wake modifier flags (WF_*)
 *
 * If (@state & @p->state) @p->state = TASK_RUNNING.
 *
 * If the task was not queued/runnable, also place it back on a runqueue.
 *
 * Atomic against schedule() which would dequeue a task, also see
 * set_current_state().
 *
 * Return: %true if @p->state changes (an actual wakeup was done),
 *	   %false otherwise.
 */
static int
try_to_wake_up(struct task_struct *p, unsigned int state, int wake_flags)
{
	return 1;
}

/**
 * wake_up_process - Wake up a specific process
 * @p: The process to be woken up.
 *
 * Attempt to wake up the nominated process and move it to the set of runnable
 * processes.
 *
 * Return: 1 if the process was woken up, 0 if it was already running.
 *
 * It may be assumed that this function implies a write memory barrier before
 * changing the task state if and only if any tasks are woken up.
 */
int wake_up_process(struct task_struct *p)
{
	return try_to_wake_up(p, TASK_NORMAL, 0);
}
