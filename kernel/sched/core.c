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
#include <lego/percpu.h>
#include <lego/jiffies.h>
#include <lego/cpumask.h>
#include <lego/spinlock.h>

DEFINE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);

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

static inline void __set_task_cpu(struct task_struct *p, unsigned int cpu)
{
#ifdef CONFIG_SMP
	task_thread_info(p)->cpu = cpu;
	p->wake_cpu = cpu;
#endif
}

/*
 * Perform scheduler related setup for a newly forked process p.
 * p is forked by current.
 *
 * __sched_fork() is basic setup used by init_idle() too:
 */
static void __sched_fork(unsigned long clone_flags, struct task_struct *p)
{
	p->on_rq = 0;
	p->static_prio = 0;
}

/*
 * fork()-time setup:
 */
int setup_sched_fork(unsigned long clone_flags, struct task_struct *p)
{
	int cpu = smp_processor_id();

	__sched_fork(clone_flags, p);

	INIT_LIST_HEAD(&p->run_list);

	/*
	 * We mark the process as NEW here. This guarantees that
	 * nobody will actually run it, and a signal or other external
	 * event cannot wake it up and insert it on the runqueue either.
	 */
	p->state = TASK_NEW;

	__set_task_cpu(p, cpu);

#if defined(CONFIG_SMP)
	p->on_cpu = 0;
#endif

	return 0;
}

void set_cpus_allowed_common(struct task_struct *p, const struct cpumask *new_mask)
{
	cpumask_copy(&p->cpus_allowed, new_mask);
	p->nr_cpus_allowed = cpumask_weight(new_mask);
}

/**
 * sched_init_idle - set up an idle thread for a given CPU
 * @idle: task in question
 * @cpu: CPU the idle task belongs to
 */
void __init sched_init_idle(struct task_struct *idle, int cpu)
{
	struct rq *rq = cpu_rq(cpu);

	__sched_fork(0, idle);

	idle->state = TASK_RUNNING;
	idle->flags |= PF_IDLE;

	set_cpus_allowed_common(idle, cpumask_of(cpu));

	__set_task_cpu(idle, cpu);

	rq->curr = rq->idle = idle;
	idle->on_rq = TASK_ON_RQ_QUEUED;
#ifdef CONFIG_SMP
	idle->on_cpu = 1;
#endif
	sprintf(idle->comm, "swapper/%d", cpu);
}

void __init sched_init(void)
{
	int i;

	for_each_possible_cpu(i) {
		struct rq *rq;

		rq = cpu_rq(i);
		spin_lock_init(&rq->lock);
		rq->nr_running = 0;
		rq->cpu = i;
		rq->online = 0;
		atomic_set(&rq->nr_iowait, 0);
	}

	/*
	 * Make us the idle thread. Technically, schedule() should not be
	 * called from this thread, however somewhere below it might be,
	 * but because we are the idle thread, we just pick up running again
	 * when this runqueue becomes "idle".
	 */
	sched_init_idle(current, smp_processor_id());
}
