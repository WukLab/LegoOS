/**//*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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
#include <lego/smpboot.h>
#include <lego/completion.h>
#include <lego/stop_machine.h>

/*
 * Structure to determine completion condition and record errors.  May
 * be shared by works on different cpus.
 */
struct cpu_stop_done {
	atomic_t		nr_todo;	/* nr left to execute */
	int			ret;		/* collected return value */
	struct completion	completion;	/* fired if nr_todo reaches 0 */
};

/* the actual stopper, one per every possible cpu, enabled on online cpus */
struct cpu_stopper {
	struct task_struct	*thread;

	spinlock_t		lock;
	bool			enabled;	/* is this stopper enabled? */
	struct list_head	works;		/* list of pending works */

	struct cpu_stop_work	stop_work;	/* for stop_cpus */
};

static DEFINE_PER_CPU(struct cpu_stopper, cpu_stopper);
static bool stop_machine_initialized = false;

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
	bool enabled;

	spin_lock_irqsave(&stopper->lock, flags);
	enabled = stopper->enabled;
	if (enabled)
		__cpu_stop_queue_work(stopper, work);
	else if (work->done)
		cpu_stop_signal_done(work->done);
	spin_unlock_irqrestore(&stopper->lock, flags);

	return enabled;
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
 * This function doesn't guarantee @cpu stays online till @fn
 * completes.  If @cpu goes down in the middle, execution may happen
 * partially or fully on different cpus.  @fn should either be ready
 * for that or the caller should ensure that @cpu stays online until
 * this function completes.
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

/**
 * try_stop_cpus - try to stop multiple cpus
 * @cpumask: cpus to stop
 * @fn: function to execute
 * @arg: argument to @fn
 *
 * Identical to stop_cpus() except that it fails with -EAGAIN if
 * someone else is already using the facility.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * -EAGAIN if someone else is already stopping cpus, -ENOENT if
 * @fn(@arg) was not executed at all because all cpus in @cpumask were
 * offline; otherwise, 0 if all executions of @fn returned 0, any non
 * zero return value if any returned non zero.
 */
int try_stop_cpus(const struct cpumask *cpumask, cpu_stop_fn_t fn, void *arg)
{
	int ret;

	/* static works are used, process one request at a time */
	if (!mutex_trylock(&stop_cpus_mutex))
		return -EAGAIN;
	ret = __stop_cpus(cpumask, fn, arg);
	mutex_unlock(&stop_cpus_mutex);
	return ret;
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

/* Called when taking CPU offline. Not used now. */
void stop_machine_park(int cpu)
{
	struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);
	/*
	 * Lockless. cpu_stopper_thread() will take stopper->lock and flush
	 * the pending works before it parks, until then it is fine to queue
	 * the new works.
	 */
	stopper->enabled = false;
	kthread_park(stopper->thread);
}

void sched_set_stop_task(int cpu, struct task_struct *stop);

static void cpu_stop_create(unsigned int cpu)
{
	sched_set_stop_task(cpu, per_cpu(cpu_stopper.thread, cpu));
}

static void cpu_stop_park(unsigned int cpu)
{
	struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);

	WARN_ON(!list_empty(&stopper->works));
}

void stop_machine_unpark(int cpu)
{
	struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);

	stopper->enabled = true;
	kthread_unpark(stopper->thread);
}

static struct smp_hotplug_thread cpu_stop_threads = {
	.store			= &cpu_stopper.thread,
	.thread_should_run	= cpu_stop_should_run,
	.thread_fn		= cpu_stopper_thread,
	.thread_comm		= "migration/%u",
	.create			= cpu_stop_create,
	.park			= cpu_stop_park,
	.selfparking		= true,
};

/*
 * Called after kthread is created
 * smpboot will create a thread on each online cpu for us.
 */
void __init cpu_stop_init(void)
{
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		struct cpu_stopper *stopper = &per_cpu(cpu_stopper, cpu);

		spin_lock_init(&stopper->lock);
		INIT_LIST_HEAD(&stopper->works);
	}

	BUG_ON(smpboot_register_percpu_thread(&cpu_stop_threads));

	/*
	 * smpboot_create_threads use kthread_create_on_cpu() to
	 * create new threads. And they are parked, too.
	 * Since we call this function after smp_init(), all CPUs
	 * are already online, thus we need to unpark them manually.
	 */
	for_each_online_cpu(cpu)
		stop_machine_unpark(cpu);

	stop_machine_initialized = true;
}
