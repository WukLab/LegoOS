/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "sched: " fmt

#include <lego/time.h>
#include <lego/mutex.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/percpu.h>
#include <lego/jiffies.h>
#include <lego/cpumask.h>
#include <lego/spinlock.h>

DEFINE_PER_CPU(int, __preempt_count) = INIT_PREEMPT_COUNT;

/* Per-CPU Runqueue */
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
	panic("%s: not implemented now\n", __func__);
}

static inline void __set_task_cpu(struct task_struct *p, unsigned int cpu)
{
#ifdef CONFIG_SMP
	task_thread_info(p)->cpu = cpu;
	p->wake_cpu = cpu;
#endif
}

static inline void
dequeue_task(struct rq *rq, struct task_struct *p, int flags)
{
	list_del_init(&p->run_list);
	rq->nr_running--;
}

static inline void
deactivate_task(struct rq *rq, struct task_struct *p, int flags)
{
	if ((p->state & TASK_UNINTERRUPTIBLE) != 0)
		rq->nr_uninterruptible++;

	dequeue_task(rq, p, flags);
}

static inline void
enqueue_task(struct rq *rq, struct task_struct *p, int flags)
{
	if ((p->state & TASK_UNINTERRUPTIBLE) != 0)
		rq->nr_uninterruptible--;

	list_add_tail(&p->run_list, &rq->rq);
	rq->nr_running++;
}

/*
 * wake_up_new_task - wake up a newly created task for the first time.
 *
 * This function will do some initial scheduler statistics housekeeping
 * that must be done for every newly created context, then puts the task
 * on the runqueue and wakes it.
 */
void wake_up_new_task(struct task_struct *p)
{
	struct rq *rq;

	p->state = TASK_RUNNING;
	__set_task_cpu(p, task_cpu(p));

	rq = task_rq(p);
	spin_lock(&rq->lock);
	enqueue_task(rq, p, 0);
	p->on_rq = TASK_ON_RQ_QUEUED;
	spin_unlock(&rq->lock);
}

void sched_remove_from_rq(struct task_struct *p)
{
	panic("%s: not implemented\n", __func__);
}

static inline struct task_struct *
pick_next_task(struct rq *rq, struct task_struct *prev)
{
	struct task_struct *next;

	if (list_empty(&rq->rq))
		/* rq empty, return idle thread */
		return rq->idle;

	if (likely(prev->on_rq)) {
		if (prev != rq->idle) {
			/*
			 * Round-Robin Policy
			 * Move this task to the tail of this rq
			 * if and only if this task is not a idle task
			 */
			list_move_tail(&prev->run_list, &rq->rq);
		}
	}

	next = container_of((&rq->rq)->next, struct task_struct, run_list);
	return next;
}

static void switch_mm_irqs_off(struct mm_struct *prev,
			       struct mm_struct *next,
			       struct task_struct *tsk)
{
	load_cr3(next->pgd);
}

/**
 * finish_task_switch - clean up after a task-switch
 * @prev: the thread we just switched away from.
 *
 * finish_task_switch must be called after the context switch
 *
 * The context switch have flipped the stack from under us and restored the
 * local variables which were saved when this task called schedule() in the
 * past. prev == current is still correct but we need to recalculate this_rq
 * because prev may have moved to another CPU.
 */
static struct rq *finish_task_switch(struct task_struct *prev)
	__releases(rq->lock)
{
	struct rq *rq = this_rq();

#ifdef CONFIG_SMP
	/*
	 * After ->on_cpu is cleared, the task can be moved to a different CPU.
	 * We must ensure this doesn't happen until the switch is completely
	 * finished.
	 */
	smp_store_release(&prev->on_cpu, 0);
#endif

	spin_unlock_irq(&rq->lock);

	/*
	 * If a task dies, then it sets TASK_DEAD in tsk->state and calls
	 * schedule one last time. The schedule call will never return.
	 */
	if (unlikely(prev->state == TASK_DEAD)) {
		put_task_struct(prev);
	}

	return rq;
}

void balance_callback(struct rq *rq)
{
	/* Do some SMP runqueue balancing */
}

/**
 * schedule_tail - first thing a freshly forked thread must call.
 * @prev: the thread we just switched away from.
 */
asmlinkage __visible void schedule_tail(struct task_struct *prev)
{
	struct rq *rq;

	rq = finish_task_switch(prev);
	balance_callback(rq);
}

/*
 * context_switch - switch to the new MM and the new thread's register state.
 */
static __always_inline struct rq *
context_switch(struct rq *rq, struct task_struct *prev, struct task_struct *next)
{
	switch_mm_irqs_off(prev->mm, next->mm, next);

	/* Here we switch the register state and the stack: */
	switch_to(prev, next, prev);
	barrier();

	return finish_task_switch(prev);
}

/*
 * __schedule() is the main scheduler function.
 *
 * The main means of driving the scheduler and thus entering this function are:
 *
 *   1. Explicit blocking: mutex, semaphore, waitqueue, etc.
 *
 *   2. TIF_NEED_RESCHED flag is checked on interrupt and userspace return
 *      paths. For example, see arch/x86/kernel/entry.S.
 *
 *      To drive preemption between tasks, the scheduler sets the flag in timer
 *      interrupt handler scheduler_tick().
 *
 *   3. Wakeups don't really cause entry into schedule(). They add a
 *      task to the run-queue and that's it.
 *
 *      Now, if the new task added to the run-queue preempts the current
 *      task, then the wakeup sets TIF_NEED_RESCHED and schedule() gets
 *      called on the nearest possible occasion:
 *
 *       - If the kernel is preemptible (CONFIG_PREEMPT=y):
 *
 *         - in syscall or exception context, at the next outmost
 *           preempt_enable(). (this might be as soon as the wake_up()'s
 *           spin_unlock()!)
 *
 *         - in IRQ context, return from interrupt-handler to
 *           preemptible context
 *
 *       - If the kernel is not preemptible (CONFIG_PREEMPT is not set)
 *         then at the next:
 *
 *          - cond_resched() call
 *          - explicit schedule() call
 *          - return from syscall or exception to user-space
 *          - return from interrupt-handler to user-space
 *
 * WARNING: must be called with preemption disabled!
 */
static void __schedule(bool preempt)
{
	struct task_struct *next, *prev;
	struct rq *rq;
	int cpu;

	cpu = smp_processor_id();
	rq = cpu_rq(cpu);
	prev = rq->curr;

	local_irq_disable();
	spin_lock(&rq->lock);

	if (!preempt && prev->state) {
		deactivate_task(rq, prev, 0);
		prev->on_rq = 0;

		if (prev->in_iowait)
			atomic_inc(&rq->nr_iowait);
	}

	/*
	 * Pick the next runnable task
	 * move prev accordingly
	 */
	next = pick_next_task(rq, prev);

	if (likely(prev != next)) {
		rq->nr_switches++;
		rq->curr = next;

		/* Also unlocks the rq: */
		rq = context_switch(rq, prev, next);
	} else {
		spin_unlock_irq(&rq->lock);
	}

	balance_callback(rq);
}

asmlinkage __visible void schedule(void)
{
	do {
		preempt_disable();
		__schedule(false);
		preempt_enable_no_resched();
	} while (need_resched());
}

/*
 * This is the entry point to schedule() from kernel preemption
 * off of irq context.
 * Note, that this is called and return with irqs disabled. This will
 * protect us against recursive calling from irq.
 */
asmlinkage __visible void preempt_schedule_irq(void)
{
	/* Catch callers which need to be fixed */
	BUG_ON(preempt_count() || !irqs_disabled());

	do {
		preempt_disable();
		local_irq_enable();
		__schedule(true);
		local_irq_disable();
		preempt_enable_no_resched();
	} while (need_resched());
}

void __noreturn do_task_dead(void)
{
	/* Causes final put_task_struct in finish_task_switch(): */
	__set_current_state(TASK_DEAD);

	__schedule(false);
	BUG();

	for (;;)
		cpu_relax();
}

/*
 * This function gets called by the timer code, with HZ frequency.
 * NOTE:
 *  1) We call it with interrupts disabled.
 *  2) We can not call schedule() here, we set TIF_NEED_RESCHED if needed
 */
void scheduler_tick(void)
{
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

	/*
	 * Initially, all RQ's curr is being
	 * set to idle thread:
	 */
	rq->curr = rq->idle = idle;

	idle->on_rq = TASK_ON_RQ_QUEUED;
#ifdef CONFIG_SMP
	idle->on_cpu = 1;
#endif

	/* Reset preempt count and inturn enable preemption */
	init_idle_preempt_count(idle, cpu);

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
		rq->nr_switches = 0;
		rq->nr_uninterruptible = 0;
		INIT_LIST_HEAD(&rq->rq);
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

	pr_info("scheduler running");
}
