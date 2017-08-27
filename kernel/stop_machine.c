/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/smp.h>
#include <lego/mutex.h>
#include <lego/kernel.h>
#include <lego/kthread.h>
#include <lego/percpu.h>
#include <lego/completion.h>
#include <lego/stop_machine.h>

struct cpu_stop_done {
	atomic_t		nr_todo;
	int			ret;
	struct completion	completion;
};

struct cpu_stopper {
	struct task_struct	*thread;

	spinlock_t		lock;
	struct list_head	works;
	struct cpu_stop_work	stop_work;
};

static DEFINE_PER_CPU(struct cpu_stopper, cpu_stopper);

/* static data for stop_cpus */
static DEFINE_MUTEX(stop_cpus_mutex);
static bool stop_cpus_in_progress;

static void cpu_stop_init_done(struct cpu_stop_done *done, unsigned int nr_todo)
{
	memset(done, 0, sizeof(*done));
	atomic_set(&done->nr_todo, nr_todo);
	init_completion(&done->completion);
}

/* signal completion unless @done is NULL */
static void cpu_stop_signal_done(struct cpu_stop_done *done)
{
	if (atomic_dec_and_test(&done->nr_todo))
		complete(&done->completion);
}

static void __cpu_stop_queue_work(struct cpu_stopper *stopper,
				  struct cpu_stop_work *work)
{
	list_add_tail(&work->list, &stopper->works);
	wake_up_process(stopper->thread);
}

/* queue @work to @stopper.  if offline, @work is completed immediately */
static bool cpu_stop_queue_work(unsigned int cpu, struct cpu_stop_work *work)
{
	struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);
	unsigned long flags;

	spin_lock_irqsave(&stopper->lock, flags);
	__cpu_stop_queue_work(stopper, work);
	spin_unlock_irqrestore(&stopper->lock, flags);

	return true;
}

/**
 * stop_one_cpu - stop a cpu
 * @cpu: cpu to stop
 * @fn: function to execute
 * @arg: argument to @fn
 *
 * Execute @fn(@arg) on @cpu.  @fn is run in a process context with
 * the highest priority preempting any task on the cpu and
 * monopolizing it.  This function returns after the execution is
 * complete.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * -ENOENT if @fn(@arg) was not executed because @cpu was offline;
 * otherwise, the return value of @fn.
 */
int stop_one_cpu(unsigned int cpu, cpu_stop_fn_t fn, void *arg)
{
	struct cpu_stop_done done;
	struct cpu_stop_work work = { .fn = fn, .arg = arg, .done = &done };

	cpu_stop_init_done(&done, 1);
	if (!cpu_stop_queue_work(cpu, &work))
		return -ENOENT;
	/*
	 * In case @cpu == smp_proccessor_id() we can avoid a sleep+wakeup
	 * cycle by doing a preemption:
	 */
	cond_resched();
	wait_for_completion(&done.completion);
	return done.ret;
}

/**
 * stop_one_cpu_nowait - stop a cpu but don't wait for completion
 * @cpu: cpu to stop
 * @fn: function to execute
 * @arg: argument to @fn
 * @work_buf: pointer to cpu_stop_work structure
 *
 * Similar to stop_one_cpu() but doesn't wait for completion.  The
 * caller is responsible for ensuring @work_buf is currently unused
 * and will remain untouched until stopper starts executing @fn.
 *
 * CONTEXT:
 * Don't care.
 *
 * RETURNS:
 * true if cpu_stop_work was queued successfully and @fn will be called,
 * false otherwise.
 */
bool stop_one_cpu_nowait(unsigned int cpu, cpu_stop_fn_t fn, void *arg,
			struct cpu_stop_work *work_buf)
{
	*work_buf = (struct cpu_stop_work){ .fn = fn, .arg = arg, };
	return cpu_stop_queue_work(cpu, work_buf);
}

static bool queue_stop_cpus_work(const struct cpumask *cpumask,
				 cpu_stop_fn_t fn, void *arg,
				 struct cpu_stop_done *done)
{
	struct cpu_stop_work *work;
	unsigned int cpu;
	bool queued = false;

	/*
	 * Disable preemption while queueing to avoid getting
	 * preempted by a stopper which might wait for other stoppers
	 * to enter @fn which can lead to deadlock.
	 */
	preempt_disable();
	stop_cpus_in_progress = true;
	for_each_cpu(cpu, cpumask) {
		work = &per_cpu(cpu_stopper.stop_work, cpu);
		work->fn = fn;
		work->arg = arg;
		work->done = done;
		if (cpu_stop_queue_work(cpu, work))
			queued = true;
	}
	stop_cpus_in_progress = false;
	preempt_enable();

	return queued;
}

static int __stop_cpus(const struct cpumask *cpumask,
		       cpu_stop_fn_t fn, void *arg)
{
	struct cpu_stop_done done;

	cpu_stop_init_done(&done, cpumask_weight(cpumask));
	if (!queue_stop_cpus_work(cpumask, fn, arg, &done))
		return -ENOENT;
	wait_for_completion(&done.completion);
	return done.ret;
}

/**
 * stop_cpus - stop multiple cpus
 * @cpumask: cpus to stop
 * @fn: function to execute
 * @arg: argument to @fn
 *
 * Execute @fn(@arg) on online cpus in @cpumask.  On each target cpu,
 * @fn is run in a process context with the highest priority
 * preempting any task on the cpu and monopolizing it.  This function
 * returns after all executions are complete.
 *
 * This function doesn't guarantee the cpus in @cpumask stay online
 * till @fn completes.  If some cpus go down in the middle, execution
 * on the cpu may happen partially or fully on different cpus.  @fn
 * should either be ready for that or the caller should ensure that
 * the cpus stay online until this function completes.
 *
 * All stop_cpus() calls are serialized making it safe for @fn to wait
 * for all cpus to start executing it.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * -ENOENT if @fn(@arg) was not executed at all because all cpus in
 * @cpumask were offline; otherwise, 0 if all executions of @fn
 * returned 0, any non zero return value if any returned non zero.
 */
int stop_cpus(const struct cpumask *cpumask, cpu_stop_fn_t fn, void *arg)
{
	int ret;

	/* static works are used, process one request at a time */
	mutex_lock(&stop_cpus_mutex);
	ret = __stop_cpus(cpumask, fn, arg);
	mutex_unlock(&stop_cpus_mutex);
	return ret;
}

static void cpu_stopper_thread(unsigned int cpu)
{
	struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);
	struct cpu_stop_work *work;

repeat:
	work = NULL;
	spin_lock_irq(&stopper->lock);
	if (!list_empty(&stopper->works)) {
		work = list_first_entry(&stopper->works,
					struct cpu_stop_work, list);
		list_del_init(&work->list);
	}
	spin_unlock_irq(&stopper->lock);

	if (work) {
		cpu_stop_fn_t fn = work->fn;
		void *arg = work->arg;
		struct cpu_stop_done *done = work->done;
		int ret;

		/* cpu stop callbacks must not sleep, make in_atomic() == T */
		preempt_count_inc();
		ret = fn(arg);
		if (done) {
			if (ret)
				done->ret = ret;
			cpu_stop_signal_done(done);
		}
		preempt_count_dec();
		WARN_ONCE(preempt_count(),
			  "cpu_stop: %pf(%p) leaked preempt count\n", fn, arg);
		goto repeat;
	}
}

static int cpu_stop_should_run(unsigned int cpu)
{
	struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);
	unsigned long flags;
	int run;

	spin_lock_irqsave(&stopper->lock, flags);
	run = !list_empty(&stopper->works);
	spin_unlock_irqrestore(&stopper->lock, flags);
	return run;
}

static int smpboot_thread_fn(void *unused)
{
	int cpu = smp_processor_id();
	struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);

	pr_debug("%d-%s, running on cpu: %d\n",
		current->pid, current->comm, cpu);

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		preempt_disable();

		if (kthread_should_park()) {
			__set_current_state(TASK_RUNNING);
			preempt_enable();
			WARN_ON(!list_empty(&stopper->works));
			kthread_parkme();

			/* We might have been woken for stop */
			continue;
		}

		if (!cpu_stop_should_run(cpu)) {
			preempt_enable_no_resched();
			schedule();
		} else {
			__set_current_state(TASK_RUNNING);
			preempt_enable();
			cpu_stopper_thread(cpu);
		}
	}

	return 0;
}

void sched_set_stop_task(int cpu, struct task_struct *stop);

void __init cpu_stop_init(void)
{
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		struct task_struct *tsk;
		struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);

		/*
		 * Simplified version of smpboot_thread_fn
		 * but keep its name anyway..
		 */
		tsk = kthread_create_on_cpu(smpboot_thread_fn, NULL, cpu,
				"migration/%d");
		BUG_ON(IS_ERR(tsk));

		/* Park first */
		kthread_park(tsk);

		get_task_struct(tsk);
		stopper->thread = tsk;
		spin_lock_init(&stopper->lock);
		INIT_LIST_HEAD(&stopper->works);

		/*
		 * Make sure it actually scheduled out into
		 * park position:
		 */
		if (!wait_task_inactive(tsk, TASK_PARKED))
			WARN_ON(1);
		else
			sched_set_stop_task(cpu, tsk);
	}
}
