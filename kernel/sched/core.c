/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/smp.h>
#include <lego/pid.h>
#include <lego/time.h>
#include <lego/mutex.h>
#include <lego/sched.h>
#include <lego/sched_rt.h>
#include <lego/kernel.h>
#include <lego/percpu.h>
#include <lego/jiffies.h>
#include <lego/cpumask.h>
#include <lego/spinlock.h>
#include <lego/syscalls.h>
#include <lego/stop_machine.h>
#include <asm/numa.h>

#include "sched.h"

bool sysctl_SCHED_FEATURE_TTWU_QUEUE = false;

int scheduler_state = SCHED_DOWN;

DEFINE_PER_CPU(int, __preempt_count) = INIT_PREEMPT_COUNT;
DEFINE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);

int in_sched_functions(unsigned long addr)
{
	return (addr >= (unsigned long)__sched_text_start
		&& addr < (unsigned long)__sched_text_end);
}

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

unsigned long long nr_context_switches(void)
{
	int i;
	unsigned long long sum = 0;

	for_each_possible_cpu(i)
		sum += cpu_rq(i)->nr_switches;

	return sum;
}

/*
 * nr_running and nr_context_switches:
 *
 * externally visible scheduler statistics: current number of runnable
 * threads, total number of context switches performed since bootup.
 */
unsigned long nr_running(void)
{
	unsigned long i, sum = 0;

	for_each_online_cpu(i)
		sum += cpu_rq(i)->nr_running;

	return sum;
}

unsigned long nr_iowait(void)
{
	unsigned long i, sum = 0;

	for_each_possible_cpu(i)
		sum += atomic_read(&cpu_rq(i)->nr_iowait);

	return sum;
}

/* TODO: more highrec and accurate clock impl */
u64 sched_clock_cpu(int cpu)
{
	return sched_clock();
}

static inline void update_rq_clock_task(struct rq *rq, s64 delta)
{
	rq->clock_task += delta;
}

void update_rq_clock(struct rq *rq)
{
	s64 delta;

	if (rq->clock_skip_update & RQCF_ACT_SKIP)
		return;

	delta = sched_clock_cpu(cpu_of(rq)) - rq->clock;
	if (delta < 0)
		return;

	rq->clock += delta;
	update_rq_clock_task(rq, delta);
}

static void set_load_weight(struct task_struct *p)
{
	int prio = p->static_prio - MAX_RT_PRIO;
	struct load_weight *load = &p->se.load;

	/*
	 * SCHED_IDLE tasks get minimal weight:
	 */
	if (idle_policy(p->policy)) {
		load->weight = WEIGHT_IDLEPRIO;
		load->inv_weight = WMULT_IDLEPRIO;
		return;
	}

	load->weight = sched_prio_to_weight[prio];
	load->inv_weight = sched_prio_to_wmult[prio];
}

static inline void
enqueue_task(struct rq *rq, struct task_struct *p, int flags)
{
	update_rq_clock(rq);
	p->sched_class->enqueue_task(rq, p, flags);
}

static inline void
dequeue_task(struct rq *rq, struct task_struct *p, int flags)
{
	update_rq_clock(rq);
	p->sched_class->dequeue_task(rq, p, flags);
}

void activate_task(struct rq *rq, struct task_struct *p, int flags)
{
	if ((p->state & TASK_UNINTERRUPTIBLE) != 0)
		rq->nr_uninterruptible--;

	enqueue_task(rq, p, flags);
}

void deactivate_task(struct rq *rq, struct task_struct *p, int flags)
{
	if ((p->state & TASK_UNINTERRUPTIBLE) != 0)
		rq->nr_uninterruptible++;

	dequeue_task(rq, p, flags);
}

/*
 * __normal_prio - return the priority that is based on the static prio
 */
static inline int __normal_prio(struct task_struct *p)
{
	return p->static_prio;
}

/*
 * Calculate the expected normal priority: i.e. priority
 * without taking RT-inheritance into account. Might be
 * boosted by interactivity modifiers. Changes upon fork,
 * setprio syscalls, and whenever the interactivity
 * estimator recalculates.
 */
static inline int normal_prio(struct task_struct *p)
{
	int prio;

	if (task_has_rt_policy(p))
		prio = MAX_RT_PRIO-1 - p->rt_priority;
	else
		prio = __normal_prio(p);
	return prio;
}

/*
 * Calculate the current priority, i.e. the priority
 * taken into account by the scheduler. This value might
 * be boosted by RT tasks, or might be boosted by
 * interactivity modifiers. Will be RT if the task got
 * RT-boosted. If not then it returns p->normal_prio.
 */
int effective_prio(struct task_struct *p)
{
	p->normal_prio = normal_prio(p);
	/*
	 * If we are RT tasks or we were boosted to RT priority,
	 * keep the priority unchanged. Otherwise, update priority
	 * to the normal priority:
	 */
	if (!rt_prio(p->prio))
		return p->normal_prio;
	return p->prio;
}

/**
 * task_curr - is this task currently executing on a CPU?
 * @p: the task in question.
 *
 * Return: 1 if the task is currently executing. 0 otherwise.
 */
inline int task_curr(const struct task_struct *p)
{
	return cpu_curr(task_cpu(p)) == p;
}

/*
 * switched_from, switched_to and prio_changed must _NOT_ drop rq->lock,
 * use the balance_callback list if you want balancing.
 *
 * this means any call to check_class_changed() must be followed by a call to
 * balance_callback().
 */
static inline void check_class_changed(struct rq *rq, struct task_struct *p,
				       const struct sched_class *prev_class,
				       int oldprio)
{
	if (prev_class != p->sched_class) {
		if (prev_class->switched_from)
			prev_class->switched_from(rq, p);

		p->sched_class->switched_to(rq, p);
	} else if (oldprio != p->prio)
		p->sched_class->prio_changed(rq, p, oldprio);
}

/*
 * task_rq_lock - lock p->pi_lock and lock the rq @p resides on.
 */
static inline struct rq *task_rq_lock(struct task_struct *p, unsigned long *flags)
	__acquires(p->pi_lock)
	__acquires(rq->lock)
{
	struct rq *rq;

	for (;;) {
		spin_lock_irqsave(&p->pi_lock, *flags);
		rq = task_rq(p);
		spin_lock(&rq->lock);
		/*
		 *	move_queued_task()		task_rq_lock()
		 *
		 *	ACQUIRE (rq->lock)
		 *	[S] ->on_rq = MIGRATING		[L] rq = task_rq()
		 *	WMB (__set_task_cpu())		ACQUIRE (rq->lock);
		 *	[S] ->cpu = new_cpu		[L] task_rq()
		 *					[L] ->on_rq
		 *	RELEASE (rq->lock)
		 *
		 * If we observe the old cpu in task_rq_lock, the acquire of
		 * the old rq->lock will fully serialize against the stores.
		 *
		 * If we observe the new cpu in task_rq_lock, the acquire will
		 * pair with the WMB to ensure we must then also see migrating.
		 */
		if (likely(rq == task_rq(p) && !task_on_rq_migrating(p))) {
			return rq;
		}
		spin_unlock(&rq->lock);
		spin_unlock_irqrestore(&p->pi_lock, *flags);

		while (unlikely(task_on_rq_migrating(p)))
			cpu_relax();
	}
}

/*
 * __task_rq_lock - lock the rq @p resides on
 */
static struct rq *__task_rq_lock(struct task_struct *p)
				 __acquires(rq->lock)
{
	struct rq *rq;

	for (;;) {
		rq = task_rq(p);
		spin_lock(&rq->lock);
		if (likely(rq == task_rq(p) && !task_on_rq_migrating(p))) {
			return rq;
		}
		spin_unlock(&rq->lock);

		while (unlikely(task_on_rq_migrating(p)))
			cpu_relax();
	}
}

/*
 * __task_rq_unlock - unlock the rq @p resides on
 */
static inline void __task_rq_unlock(struct rq *rq)
				    __releases(rq->lock)
{
	spin_unlock(&rq->lock);
}

static inline void
task_rq_unlock(struct rq *rq, struct task_struct *p, unsigned long *flags)
	__releases(rq->lock)
	__releases(p->pi_lock)
{
	spin_unlock(&rq->lock);
	spin_unlock_irqrestore(&p->pi_lock, *flags);
}

static inline void __set_task_cpu(struct task_struct *p, unsigned int cpu)
{
#ifdef CONFIG_SMP
	/*
	 * After ->cpu is set up to a new value, task_rq_lock(p, ...) can be
	 * successfuly executed on another CPU. We must ensure that updates of
	 * per-task data have been completed by this moment.
	 */
	smp_wmb();
	task_thread_info(p)->cpu = cpu;
	p->wake_cpu = cpu;
#endif
}

#ifdef CONFIG_SMP
/*
 * This is how migration works:
 *
 * 1) we invoke migration_cpu_stop() on the target CPU using
 *    stop_one_cpu().
 * 2) stopper starts to run (implicitly forcing the migrated thread
 *    off the CPU)
 * 3) it checks whether the migrated task is still in the wrong runqueue.
 * 4) if it's in the wrong runqueue then the migration thread removes
 *    it and puts it into the right queue.
 * 5) stopper completes and stop_one_cpu() returns and the migration
 *    is done.
 */

/*
 * Move a queued task to a new rq
 * Must enter with old rq's lock held!
 *
 * Returns (locked) new rq. Old rq's lock is released
 */
static struct rq *
move_queued_task(struct rq *rq, struct task_struct *p, int new_cpu)
{
	/* pop from old rq */
	p->on_rq = TASK_ON_RQ_MIGRATING;
	dequeue_task(rq, p, 0);
	set_task_cpu(p, new_cpu);
	spin_unlock(&rq->lock);

	/* push to new rq */
	rq = cpu_rq(new_cpu);
	spin_lock(&rq->lock);
	BUG_ON(task_cpu(p) != new_cpu);
	enqueue_task(rq, p, 0);
	p->on_rq = TASK_ON_RQ_QUEUED;
	check_preempt_curr(rq, p, 0);

	return rq;
}

struct migration_arg {
	struct task_struct *task;
	int dest_cpu;
};

/*
 * Move (not current) task off this CPU, onto the destination CPU. We're doing
 * this because either it can't run here any more (set_cpus_allowed()
 * away from this CPU, or CPU going down), or because we're
 * attempting to rebalance this task on exec (sched_exec).
 *
 * So we race with normal scheduler movements, but that's OK, as long
 * as the task is no longer on this CPU.
 */
struct rq *__migrate_task(struct rq *rq, struct task_struct *p, int dest_cpu)
{
	if (unlikely(!cpu_online(dest_cpu)))
		return rq;

	/* Affinity changed (again). */
	if (!cpumask_test_cpu(dest_cpu, &p->cpus_allowed))
		return rq;

	rq = move_queued_task(rq, p, dest_cpu);

	return rq;
}

/*
 * migration_cpu_stop - this will be executed by a highprio stopper thread
 * and performs thread migration by bumping thread off CPU then
 * 'pushing' onto another runqueue.
 */
static int migration_cpu_stop(void *data)
{
	struct migration_arg *arg = data;
	struct task_struct *p = arg->task;
	struct rq *rq = this_rq();

	/*
	 * The original target cpu might have gone down and we might
	 * be on another cpu but it doesn't matter.
	 */
	local_irq_disable();

	/*
	 * We need to explicitly wake pending tasks before running
	 * __migrate_task() such that we will not miss enforcing cpus_allowed
	 * during wakeups, see set_cpus_allowed_ptr()'s TASK_WAKING test.
	 */
	sched_ttwu_pending();

	spin_lock(&p->pi_lock);
	spin_lock(&rq->lock);
	/*
	 * If task_rq(p) != rq, it cannot be migrated here, because we're
	 * holding rq->lock, if p->on_rq == 0 it cannot get enqueued because
	 * we're holding p->pi_lock.
	 */
	if (task_rq(p) == rq) {
		if (task_on_rq_queued(p))
			rq = __migrate_task(rq, p, arg->dest_cpu);
		else
			p->wake_cpu = arg->dest_cpu;
	}
	spin_unlock(&rq->lock);
	spin_unlock(&p->pi_lock);

	local_irq_enable();
	return 0;
}

void set_cpus_allowed_common(struct task_struct *p, const struct cpumask *new_mask)
{
	cpumask_copy(&p->cpus_allowed, new_mask);
	p->nr_cpus_allowed = cpumask_weight(new_mask);
}

void do_set_cpus_allowed(struct task_struct *p, const struct cpumask *new_mask)
{
	struct rq *rq = task_rq(p);
	bool queued, running;

	queued = task_on_rq_queued(p);
	running = task_current(rq, p);

	if (queued)
		dequeue_task(rq, p, DEQUEUE_SAVE);
	if (running)
		put_prev_task(rq, p);

	p->sched_class->set_cpus_allowed(p, new_mask);

	if (running)
		p->sched_class->set_curr_task(rq);
	if (queued)
		enqueue_task(rq, p, ENQUEUE_RESTORE);
}

/*
 * Change a given task's CPU affinity. Migrate the thread to a
 * proper CPU and schedule it away if the CPU it's executing on
 * is removed from the allowed bitmask.
 *
 * NOTE: the caller must have a valid reference to the task, the
 * task must not exit() & deallocate itself prematurely. The
 * call is not atomic; no spinlocks may be held.
 */
static int __set_cpus_allowed_ptr(struct task_struct *p,
				  const struct cpumask *new_mask, bool check)
{
	unsigned long flags;
	struct rq *rq;
	unsigned int dest_cpu;
	int ret = 0;

	rq = task_rq_lock(p, &flags);

	/*
	 * Must re-check here, to close a race against __kthread_bind(),
	 * sched_setaffinity() is not guaranteed to observe the flag.
	 */
	if (check && (p->flags & PF_NO_SETAFFINITY)) {
		ret = -EINVAL;
		goto out;
	}

	if (cpumask_equal(&p->cpus_allowed, new_mask))
		goto out;

	if (!cpumask_intersects(new_mask, cpu_active_mask)) {
		ret = -EINVAL;
		goto out;
	}

	do_set_cpus_allowed(p, new_mask);

	/* Can the task run on the task's current CPU? If so, we're done */
	if (cpumask_test_cpu(task_cpu(p), new_mask))
		goto out;

	dest_cpu = cpumask_any_and(cpu_active_mask, new_mask);
	if (task_running(rq, p) || p->state == TASK_WAKING) {
		struct migration_arg arg = { p, dest_cpu };

		/*
		 * We can not move ourself to @dest_cpu,
		 * need help from migration thread: drop lock and wait.
		 * When stop_one_cpu() returns, we will be running on @dest_cpu.
		 */
		task_rq_unlock(rq, p, &flags);
		stop_one_cpu(cpu_of(rq), migration_cpu_stop, &arg);
		return 0;
	} else if (task_on_rq_queued(p))
		rq = move_queued_task(rq, p, dest_cpu);

out:
	task_rq_unlock(rq, p, &flags);

	return ret;
}

int set_cpus_allowed_ptr(struct task_struct *p, const struct cpumask *new_mask)
{
	return __set_cpus_allowed_ptr(p, new_mask, false);
}

void set_task_cpu(struct task_struct *p, unsigned int new_cpu)
{
	/*
	 * We should never call set_task_cpu() on a blocked task,
	 * ttwu() will sort out the placement.
	 */
	WARN_ON_ONCE(p->state != TASK_RUNNING && p->state != TASK_WAKING &&
			!p->on_rq);

	__set_task_cpu(p, new_cpu);
}

#else

static inline int
__set_cpus_allowed_ptr(struct task_struct *p, const struct cpumask *new_mask,
		       bool check)
{
	return set_cpus_allowed_ptr(p, new_mask);
}

#endif

/**
 * sched_setscheduler_nocheck - change the scheduling policy and/or RT priority of a thread from kernelspace.
 * @p: the task in question.
 * @policy: new policy.
 * @param: structure containing the new RT priority.
 *
 * Just like sched_setscheduler, only don't bother checking if the
 * current context has permission.  For example, this is needed in
 * stop_machine(): we create temporary high priority worker threads,
 * but our caller might not have that capability.
 *
 * Return: 0 on success. An error code otherwise.
 */
int sched_setscheduler_nocheck(struct task_struct *p, int policy,
			       const struct sched_param *param)
{
	return 0;
}

void sched_set_stop_task(int cpu, struct task_struct *stop)
{
	struct sched_param param = { .sched_priority = MAX_RT_PRIO - 1 };
	struct task_struct *old_stop = cpu_rq(cpu)->stop;

	if (stop) {
		/*
		 * Make it appear like a SCHED_FIFO task, its something
		 * userspace knows about and won't get confused about.
		 */
		sched_setscheduler_nocheck(stop, SCHED_FIFO, &param);

		stop->sched_class = &stop_sched_class;
	}

	cpu_rq(cpu)->stop = stop;

	if (old_stop) {
		/*
		 * Reset it back to a normal scheduling class so that
		 * it can die in pieces.
		 */
		old_stop->sched_class = &rt_sched_class;
	}
}

/**
 * sched_setaffinity	-	Set cpu affinity for a task
 * @pid: the task pid in question
 * @new_mask: the new cpumask affinity
 *
 * Return: 0 on success, EAGAIN if the pid is currently running
 * on this cpu.
 */
long sched_setaffinity(pid_t pid, const struct cpumask *new_mask)
{
	int ret;
	struct task_struct *p;

	if (pid == 0)
		p = current;
	else {
		p = find_task_by_pid(pid);
		if (!p)
			return -ESRCH;
	}

	/* Prevent p going away */
	get_task_struct(p);

	if (p->flags & PF_NO_SETAFFINITY) {
		ret = -EINVAL;
		goto out_put_task;
	}

	ret = set_cpus_allowed_ptr(p, new_mask);

out_put_task:
	put_task_struct(p);
	return ret;
}

static int get_user_cpu_mask(unsigned long __user *user_mask_ptr, unsigned len,
			     struct cpumask *new_mask)
{
	if (len < cpumask_size())
		cpumask_clear(new_mask);
	else if (len > cpumask_size())
		len = cpumask_size();

	return copy_from_user(new_mask, user_mask_ptr, len) ? -EFAULT : 0;
}

/**
 * sys_sched_setaffinity - set the cpu affinity of a process
 * @pid: pid of the process
 * @len: length in bytes of the bitmask pointed to by user_mask_ptr
 * @user_mask_ptr: user-space pointer to the new cpu mask
 *
 * Return: 0 on success. An error code otherwise.
 */
SYSCALL_DEFINE3(sched_setaffinity, pid_t, pid, unsigned int, len,
		unsigned long __user *, user_mask_ptr)
{
	cpumask_var_t new_mask;
	int retval;

	retval = get_user_cpu_mask(user_mask_ptr, len, new_mask);
	if (retval)
		goto out;

#ifdef CONFIG_DEBUG_SYSCALL
	do {
		char buf[64];

		scnprintf(buf, 64, "%*pbl", num_online_cpus(), new_mask);
		syscall_enter("pid:%d,len:%u,user_mask_ptr:%p->cpulist:%s\n",
			pid, len, user_mask_ptr, buf);

	} while (0);
#endif

	retval = sched_setaffinity(pid, new_mask);

out:
	syscall_exit(retval);
	return retval;
}

long sched_getaffinity(pid_t pid, struct cpumask *mask)
{
	struct task_struct *p;
	unsigned long flags;
	int retval;

	if (pid == 0)
		p = current;
	else {
		p = find_task_by_pid(pid);
		if (!p) {
			retval = -ESRCH;
			goto out;
		}
	}

	retval = 0;
	spin_lock_irqsave(&p->pi_lock, flags);
	cpumask_and(mask, &p->cpus_allowed, cpu_active_mask);
	spin_unlock_irqrestore(&p->pi_lock, flags);
out:
	return retval;
}

/**
 * sys_sched_getaffinity - get the cpu affinity of a process
 * @pid: pid of the process
 * @len: length in bytes of the bitmask pointed to by user_mask_ptr
 * @user_mask_ptr: user-space pointer to hold the current cpu mask
 *
 * Return: size of CPU mask copied to user_mask_ptr on success. An
 * error code otherwise.
 */
SYSCALL_DEFINE3(sched_getaffinity, pid_t, pid, unsigned int, len,
		unsigned long __user *, user_mask_ptr)
{
	int ret;
	cpumask_var_t mask;

	if ((len * BITS_PER_BYTE) < nr_cpu_ids) {
		ret = -EINVAL;
		goto out;
	}
	if (len & (sizeof(unsigned long)-1)) {
		ret = -EINVAL;
		goto out;
	}

	ret = sched_getaffinity(pid, mask);
	if (ret == 0) {
		size_t retlen = min_t(size_t, len, cpumask_size());

		if (copy_to_user(user_mask_ptr, mask, retlen))
			ret = -EFAULT;
		else
			ret = retlen;
	}

#ifdef CONFIG_DEBUG_SYSCALL
	do {
		char buf[64];

		scnprintf(buf, 64, "%*pbl", num_online_cpus(), mask);
		syscall_enter("pid: %d, len: %u, user_mask_ptr: %p -> cpulist: %s\n",
			pid, len, user_mask_ptr, buf);

	} while (0);
#endif

out:
	syscall_exit(ret);
	return ret;
}

void sched_remove_from_rq(struct task_struct *p)
{
	panic("%s: not implemented\n", __func__);
}

/*
 * Pick up the highest-prio task:
 */
static inline struct task_struct *
pick_next_task(struct rq *rq, struct task_struct *prev)
{
	struct task_struct *p;
	const struct sched_class *class;

again:
	for_each_class(class) {
		p = class->pick_next_task(rq, prev);
		if (p) {
			if (unlikely(p == RETRY_TASK))
				goto again;
			return p;
		}
	}

	/* idle class will always have a runnable task */
	BUG();
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
	long prev_state;

#ifdef CONFIG_PREEMPT
	/*
	 * The previous task will have left us with a preempt_count of 2
	 * because it left us after:
	 *
	 *	schedule()
	 *	  preempt_disable();			// 1
	 *	  __schedule()
	 *	    spin_lock_irq(&rq->lock)		// 2
	 */
	if (WARN_ONCE(preempt_count() != 2,
		      "corrupted preempt_count: %s/%d/0x%x\n",
		      current->comm, current->pid, preempt_count()))
		preempt_count_set(2);

#endif

	/*
	 * A task struct has one reference for the use as "current".
	 * If a task dies, then it sets TASK_DEAD in tsk->state and calls
	 * schedule one last time. The schedule call will never return, and
	 * the scheduled task must drop that reference.
	 *
	 * We must observe prev->state before clearing prev->on_cpu,
	 * otherwise a concurrent wakeup can get prev running on another CPU
	 * and we could rave with its RUNNING -> DEAD transition, resulting
	 * in a double drop.
	 */
	prev_state = prev->state;

#ifdef CONFIG_SMP
	/*
	 * After ->on_cpu is cleared, the task can be moved to a different CPU.
	 * We must ensure this doesn't happen until the switch is completely
	 * finished.
	 *
	 * In particular, the load of prev->state above must happen before this.
	 *
	 * Pairs with the smp_cond_load_acquire() in try_to_wake_up().
	 */
	smp_store_release(&prev->on_cpu, 0);
#endif

	spin_unlock_irq(&rq->lock);

	/*
	 * If a task dies, then it sets TASK_DEAD in tsk->state and calls
	 * schedule one last time. The schedule call will never return.
	 */
	if (unlikely(prev_state == TASK_DEAD)) {
		if (prev->sched_class->task_dead)
			prev->sched_class->task_dead(prev);

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

	/*
	 * finish_task_switch() will drop rq->lock() and lower preempt_count
	 * and the preempt_enable() will end up enabling preemption.
	 */
	rq = finish_task_switch(prev);
	preempt_enable();
	balance_callback(rq);

	/*
	 * $ man set_tid_address
	 * When set_child_tid is set, the very first thing the new process
	 * does is writing its PID at this address:
	 */
	if (current->set_child_tid)
		put_user(current->pid, current->set_child_tid);
}

/*
 * context_switch - switch to the new MM and the new thread's register state.
 */
static __always_inline struct rq *
context_switch(struct rq *rq, struct task_struct *prev, struct task_struct *next)
{
#ifdef CONFIG_SMP
	/*
	 * We can optimise this out completely for !SMP, because the
	 * SMP rebalancing from interrupt is the only thing that cares
	 * here.
	 */
	next->on_cpu = 1;
#endif

	/*
	 * @prev might already call do_task_dead()
	 * which means @prev->mm can be NULL
	 * proceed with caution
	 *	- ys
	 */
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
static void __sched __schedule(bool preempt)
{
	struct task_struct *next, *prev;
	unsigned long *switch_count;
	struct rq *rq;
	int cpu;

	cpu = smp_processor_id();
	rq = cpu_rq(cpu);
	prev = rq->curr;

	local_irq_disable();
	spin_lock(&rq->lock);

	/*
	 *		CPU0, task p
	 *
	 *		current->state = TASK_UNINTERRUPTIBLE;
	 *		  .
	 *		  .
	 *  <int>
	 * preempt_schedule_irq()
	 *  <eoi>
	 *		  .
	 *		  .
	 *		schedule()
	 *
	 * If the current task just changed task state and was
	 * intending to sleep, but got preempted in the middle.
	 * In this case, we should NOT deactivate this task by
	 * preemption.
	 *
	 * Preemption means
	 *	DO NOT TOUCH ANYTHING
	 *	DO NOT CHANGE ANY STATES
	 * of the previous task.
	 */
	switch_count = &prev->nivcsw;
	if (!preempt && prev->state) {
		if (unlikely(signal_pending_state(prev->state, prev))) {
			prev->state = TASK_RUNNING;
		} else {
			deactivate_task(rq, prev, DEQUEUE_SLEEP);
			prev->on_rq = 0;

			if (prev->in_iowait)
				atomic_inc(&rq->nr_iowait);
		}

		/* voluntary context switch */
		switch_count = &prev->nvcsw;
	}

	if (task_on_rq_queued(prev))
		update_rq_clock(rq);

	next = pick_next_task(rq, prev);
	clear_tsk_need_resched(prev);
	rq->clock_skip_update = 0;

	if (likely(prev != next)) {
		rq->nr_switches++;
		rq->curr = next;
		++*switch_count;

		/* Also unlocks the rq: */
		rq = context_switch(rq, prev, next);
	} else {
		spin_unlock_irq(&rq->lock);
	}

	balance_callback(rq);
}

asmlinkage __visible void __sched schedule(void)
{
	do {
		preempt_disable();
		__schedule(false);
		preempt_enable_no_resched();
	} while (need_resched());
}

/**
 * schedule_preempt_disabled - called with preemption disabled
 *
 * Returns with preemption disabled. Note: preempt_count must be 1
 */
void __sched schedule_preempt_disabled(void)
{
#ifdef CONFIG_PREEMPT
	BUG_ON(preempt_count() != 1);
#endif
	preempt_enable_no_resched();
	schedule();
	preempt_disable();
}

/*
 * This is the entry point to schedule() from kernel preemption
 * off of irq context.
 * Note, that this is called and return with irqs disabled. This will
 * protect us against recursive calling from irq.
 */
asmlinkage __visible void __sched preempt_schedule_irq(void)
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

#ifndef CONFIG_PREEMPT
static void __sched preempt_schedule_common(void)
{
	do {
		preempt_disable();
		__schedule(true);
		preempt_enable_no_resched();

		/*
		 * Check again in case we missed a preemption opportunity
		 * between schedule and now.
		 */
	} while (need_resched());
}

int __sched _cond_resched(void)
{
	if (need_resched()) {
		preempt_schedule_common();
		return 1;
	}
	return 0;
}
#endif

/**
 * Called while a thread has done its job
 * WARNING: Must enter with preemption disabled!
 */
void __noreturn do_task_dead(void)
{
	/* Causes final put_task_struct in finish_task_switch(): */
	__set_current_state(TASK_DEAD);

	__schedule(false);
	BUG();

	/* Avoid "noreturn function does return".  */
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
	int cpu = smp_processor_id();
	struct rq *rq = cpu_rq(cpu);
	struct task_struct *curr = rq->curr;

	spin_lock(&rq->lock);
	update_rq_clock(rq);
	curr->sched_class->task_tick(rq, curr, 0);
	spin_unlock(&rq->lock);
}

/*
 * resched_curr - mark rq's current task 'to be rescheduled now'.
 *
 * On UP this means the setting of the need_resched flag, on SMP it
 * might also involve a cross-CPU call to trigger the scheduler on
 * the target CPU.
 */
void resched_curr(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	int cpu;

	if (test_tsk_need_resched(curr))
		return;

	cpu = cpu_of(rq);

	set_tsk_need_resched(curr);

	if (cpu != smp_processor_id())
		smp_send_reschedule(cpu);
}

/*
 * Mark the task runnable and perform wakeup-preemption.
 */
static void ttwu_do_wakeup(struct rq *rq, struct task_struct *p, int wake_flags)
{
	check_preempt_curr(rq, p, wake_flags);
	p->state = TASK_RUNNING;
#ifdef CONFIG_SMP
	if (p->sched_class->task_woken)
		p->sched_class->task_woken(rq, p);
#endif
}

static inline void ttwu_activate(struct rq *rq, struct task_struct *p, int en_flags)
{
	activate_task(rq, p, en_flags);
	p->on_rq = TASK_ON_RQ_QUEUED;

#if 0
	/* if a worker is waking up, notify workqueue */
	if (p->flags & PF_WQ_WORKER)
		wq_worker_waking_up(p, cpu_of(rq));
#endif
}

static void
ttwu_do_activate(struct rq *rq, struct task_struct *p, int wake_flags)
{
	int en_flags = ENQUEUE_WAKEUP;

#ifdef CONFIG_SMP
	if (wake_flags & WF_MIGRATED)
		en_flags |= ENQUEUE_MIGRATED;
#endif
	ttwu_activate(rq, p, en_flags);
	ttwu_do_wakeup(rq, p, wake_flags);
}

#ifdef CONFIG_SMP
void sched_ttwu_pending(void)
{
	struct rq *rq = this_rq();
	struct llist_node *llist = llist_del_all(&rq->wake_list);
	struct task_struct *p;
	unsigned long flags;

	if (!llist)
		return;

	spin_lock_irqsave(&rq->lock, flags);

	while (llist) {
		int wake_flags = 0;

		p = llist_entry(llist, struct task_struct, wake_entry);
		llist = llist_next(llist);

		if (p->sched_remote_wakeup)
			wake_flags = WF_MIGRATED;

		ttwu_do_activate(rq, p, wake_flags);
	}

	spin_unlock_irqrestore(&rq->lock, flags);
}

void scheduler_ipi(void)
{
	if (llist_empty(&this_rq()->wake_list))
		return;
	sched_ttwu_pending();
}

static void ttwu_queue_remote(struct task_struct *p, int cpu, int wake_flags)
{
	p->sched_remote_wakeup = !!(wake_flags & WF_MIGRATED);

	if (llist_add(&p->wake_entry, &cpu_rq(cpu)->wake_list))
		smp_send_reschedule(cpu);
}
#endif

void wake_q_add(struct wake_q_head *head, struct task_struct *task)
{
	struct wake_q_node *node = &task->wake_q;

	/*
	 * Atomically grab the task, if ->wake_q is !nil already it means
	 * its already queued (either by us or someone else) and will get the
	 * wakeup due to that.
	 *
	 * This cmpxchg() implies a full barrier, which pairs with the write
	 * barrier implied by the wakeup in wake_up_q().
	 */
	if (cmpxchg(&node->next, NULL, WAKE_Q_TAIL))
		return;

	get_task_struct(task);

	/*
	 * The head is context local, there can be no concurrency.
	 */
	*head->lastp = node;
	head->lastp = &node->next;
}

void wake_up_q(struct wake_q_head *head)
{
	struct wake_q_node *node = head->first;

	while (node != WAKE_Q_TAIL) {
		struct task_struct *task;

		task = container_of(node, struct task_struct, wake_q);
		BUG_ON(!task);
		/* task can safely be re-inserted now */
		node = node->next;
		task->wake_q.next = NULL;

		/*
		 * wake_up_process() implies a wmb() to pair with the queueing
		 * in wake_q_add() so as not to miss wakeups.
		 */
		wake_up_process(task);
		put_task_struct(task);
	}
}

/*
 * Called in case the task @p isn't fully descheduled from its runqueue,
 * in this case we must do a remote wakeup. Its a 'light' wakeup though,
 * since all we need to do is flip p->state to TASK_RUNNING, since
 * the task is still ->on_rq.
 */
static int ttwu_remote(struct task_struct *p, int wake_flags)
{
	struct rq *rq;
	int ret = 0;

	rq = __task_rq_lock(p);
	if (task_on_rq_queued(p)) {
		/* check_preempt_curr() may use rq clock */
		update_rq_clock(rq);
		ttwu_do_wakeup(rq, p, wake_flags);
		ret = 1;
	}
	__task_rq_unlock(rq);

	return ret;
}

static void ttwu_queue(struct task_struct *p, int cpu, int wake_flags)
{
	struct rq *rq = cpu_rq(cpu);

#ifdef CONFIG_SMP
	if (sysctl_SCHED_FEATURE_TTWU_QUEUE) {
		/*
		 * Queue this task on remote rq and send reschedule IPI
		 * in order to reduce rq lock contention.
		 */
		sched_clock_cpu(cpu); /* sync clocks x-cpu */
		ttwu_queue_remote(p, cpu, wake_flags);
		return;
	}
#endif

	spin_lock(&rq->lock);
	ttwu_do_activate(rq, p, wake_flags);
	spin_unlock(&rq->lock);
}

static int select_fallback_rq(int cpu, struct task_struct *p)
{
	int nid = cpu_to_node(cpu);
	int dest_cpu;
	const struct cpumask *nodemask = NULL;

	/*
	 * If the node that the cpu is on has been offlined, cpu_to_node()
	 * will return -1. There is no cpu on the node, and we should
	 * select the cpu on the other node.
	 */
	if (nid != -1) {
		nodemask = cpumask_of_node(nid);

		/* Look for allowed, online CPU in same node. */
		for_each_cpu(dest_cpu, nodemask) {
			if (!cpu_active(dest_cpu))
				continue;
			if (cpumask_test_cpu(dest_cpu, &p->cpus_allowed))
				return dest_cpu;
		}
	}

	for (;;) {
		/* Any allowed, online CPU? */
		for_each_cpu(dest_cpu, &p->cpus_allowed) {
			if (!(p->flags & PF_KTHREAD) && !cpu_active(dest_cpu))
				continue;
			if (!cpu_online(dest_cpu))
				continue;
			goto out;
		}
	}
out:
	return dest_cpu;
}

static inline
int select_task_rq(struct task_struct *p, int cpu, int sd_flags, int wake_flags)
{
	if (p->nr_cpus_allowed > 1)
		cpu = p->sched_class->select_task_rq(p, cpu, sd_flags, wake_flags);
	else
		cpu = cpumask_any(&p->cpus_allowed);

	/*
	 * In order not to call set_task_cpu() on a blocking task we need
	 * to rely on ttwu() to place the task on a valid ->cpus_allowed
	 * cpu.
	 *
	 * Since this is common to all placement strategies, this lives here.
	 *
	 * [ this allows ->select_task() to simply return task_cpu(p) and
	 *   not worry about this generic constraint ]
	 */
	if (unlikely(!cpumask_test_cpu(cpu, &p->cpus_allowed) ||
		     !cpu_active(cpu)))
		cpu = select_fallback_rq(task_cpu(p), p);

	return cpu;
}

/* Check if @p should preempt current running thread */
void check_preempt_curr(struct rq *rq, struct task_struct *p, int flags)
{
	const struct sched_class *class;

	if (p->sched_class == rq->curr->sched_class) {
		rq->curr->sched_class->check_preempt_curr(rq, p, flags);
	} else {
		for_each_class(class) {
			if (class == rq->curr->sched_class)
				break;
			if (class == p->sched_class) {
				resched_curr(rq);
				break;
			}
		}
	}

	/*
	 * A queue event has occurred, and we're going to schedule.  In
	 * this case, we can save a useless back to back clock update.
	 */
	if (task_on_rq_queued(rq->curr) && test_tsk_need_resched(rq->curr))
		rq_clock_skip_update(rq, true);
}

/**
 * try_to_wake_up - wake up a thread
 * @p: the thread to be awakened
 * @state: the mask of task states that can be woken
 * @wake_flags: wake modifier flags (WF_*)
 *
 * Put it on the run-queue if it's not already there. The "current"
 * thread is always on the run-queue (except when the actual
 * re-schedule is in progress), and as such you're allowed to do
 * the simpler "current->state = TASK_RUNNING" to mark yourself
 * runnable without the overhead of this.
 *
 * Return:
 * 	1 if @p was woken up,
 *	0 if it was already running.
 *	  or @state didn't match @p's state.
 */
int try_to_wake_up(struct task_struct *p, unsigned int state, int wake_flags)
{
	unsigned long flags;
	int cpu, success = 0;

	/*
	 * If we are going to wake up a thread waiting for CONDITION we
	 * need to ensure that CONDITION=1 done by the caller can not be
	 * reordered with p->state check below. This pairs with mb() in
	 * set_current_state() the waiting thread does.
	 */
	smp_mb__before_spinlock();
	spin_lock_irqsave(&p->pi_lock, flags);
	if (!(p->state & state))
		goto out;

	success = 1;
	cpu = task_cpu(p);

	/*
	 * Ensure we load p->on_rq _after_ p->state, otherwise it would
	 * be possible to, falsely, observe p->on_rq == 0 and get stuck
	 * in smp_cond_load_acquire() below.
	 *
	 * sched_ttwu_pending()                 try_to_wake_up()
	 *   [S] p->on_rq = 1;                  [L] P->state
	 *       UNLOCK rq->lock  -----.
	 *                              \
	 *				 +---   RMB
	 * schedule()                   /
	 *       LOCK rq->lock    -----'
	 *       UNLOCK rq->lock
	 *
	 * [task p]
	 *   [S] p->state = UNINTERRUPTIBLE     [L] p->on_rq
	 *
	 * Pairs with the UNLOCK+LOCK on rq->lock from the
	 * last wakeup of our task and the schedule that got our task
	 * current.
	 */
	smp_rmb();
	if (p->on_rq && ttwu_remote(p, wake_flags))
		goto out;

#ifdef CONFIG_SMP
	/*
	 * Ensure we load p->on_cpu _after_ p->on_rq, otherwise it would be
	 * possible to, falsely, observe p->on_cpu == 0.
	 *
	 * One must be running (->on_cpu == 1) in order to remove oneself
	 * from the runqueue.
	 *
	 *  [S] ->on_cpu = 1;	[L] ->on_rq
	 *      UNLOCK rq->lock
	 *			RMB
	 *      LOCK   rq->lock
	 *  [S] ->on_rq = 0;    [L] ->on_cpu
	 *
	 * Pairs with the full barrier implied in the UNLOCK+LOCK on rq->lock
	 * from the consecutive calls to schedule(); the first switching to our
	 * task, the second putting it to sleep.
	 */
	smp_rmb();

	/*
	 * If the owning (remote) cpu is still in the middle of schedule() with
	 * this task as prev, wait until its done referencing the task.
	 *
	 * Pairs with the smp_store_release() in finish_lock_switch().
	 *
	 * This ensures that tasks getting woken will be fully ordered against
	 * their previous state and preserve Program Order.
	 */
	smp_cond_load_acquire(&p->on_cpu, !VAL);

	p->state = TASK_WAKING;

	cpu = select_task_rq(p, p->wake_cpu, SD_BALANCE_WAKE, wake_flags);
	if (task_cpu(p) != cpu) {
		wake_flags |= WF_MIGRATED;
		set_task_cpu(p, cpu);
	}
#endif

	ttwu_queue(p, cpu, wake_flags);
out:
	spin_unlock_irqrestore(&p->pi_lock, flags);
	return success;
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

int wake_up_state(struct task_struct *p, unsigned int state)
{
	return try_to_wake_up(p, state, 0);
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
	unsigned long flags;
	struct rq *rq;

	spin_lock_irqsave(&p->pi_lock, flags);

	p->state = TASK_RUNNING;

	/* Select a CPU for new thread to run */
#ifdef CONFIG_SMP
	/*
	 * Fork balancing, do it here and not earlier because:
	 *  - cpus_allowed can change in the fork path
	 *  - any previously selected cpu might disappear through hotplug
	 */
	set_task_cpu(p, select_task_rq(p, task_cpu(p), SD_BALANCE_FORK, 0));
#endif

	rq = __task_rq_lock(p);
	activate_task(rq, p, 0);
	p->on_rq = TASK_ON_RQ_QUEUED;

	/* preempt current if needed */
	check_preempt_curr(rq, p, WF_FORK);

	task_rq_unlock(rq, p, &flags);
}

/*
 * wait_task_inactive - wait for a thread to unschedule.
 *
 * If @match_state is nonzero, it's the @p->state value just checked and
 * not expected to change.  If it changes, i.e. @p might have woken up,
 * then return zero.  When we succeed in waiting for @p to be off its CPU,
 * we return a positive number (its total switch count).  If a second call
 * a short while later returns the same number, the caller can be sure that
 * @p has remained unscheduled the whole time.
 *
 * The caller must ensure that the task *will* unschedule sometime soon,
 * else this function might spin for a *long* time. This function can't
 * be called with interrupts off, or it may introduce deadlock with
 * smp_call_function() if an IPI is sent by the same process we are
 * waiting to become inactive.
 */
unsigned long wait_task_inactive(struct task_struct *p, long match_state)
{
	int running, queued;
	unsigned long flags;
	unsigned long ncsw;
	struct rq *rq;

	for (;;) {
		/*
		 * We do the initial early heuristics without holding
		 * any task-queue locks at all. We'll only try to get
		 * the runqueue lock when things look like they will
		 * work out!
		 */
		rq = task_rq(p);

		/*
		 * If the task is actively running on another CPU
		 * still, just relax and busy-wait without holding
		 * any locks.
		 *
		 * NOTE! Since we don't hold any locks, it's not
		 * even sure that "rq" stays as the right runqueue!
		 * But we don't care, since "task_running()" will
		 * return false if the runqueue has changed and p
		 * is actually now running somewhere else!
		 */
		while (task_running(rq, p)) {
			if (match_state && unlikely(p->state != match_state))
				return 0;
			cpu_relax();
		}

		/*
		 * Ok, time to look more closely! We need the rq
		 * lock now, to be *sure*. If we're wrong, we'll
		 * just go back and repeat.
		 */
		rq = task_rq_lock(p, &flags);
		running = task_running(rq, p);
		queued = task_on_rq_queued(p);
		ncsw = 0;
		if (!match_state || p->state == match_state)
			ncsw = p->nvcsw | LONG_MIN; /* sets MSB */
		task_rq_unlock(rq, p, &flags);

		/*
		 * If it changed from the expected state, bail out now.
		 */
		if (unlikely(!ncsw))
			break;

		/*
		 * Was it really running after all now that we
		 * checked with the proper locks actually held?
		 *
		 * Oops. Go back and try again..
		 */
		if (unlikely(running)) {
			cpu_relax();
			continue;
		}

		/*
		 * It's not enough that it's not actively running,
		 * it must be off the runqueue _entirely_, and not
		 * preempted!
		 *
		 * So if it was still runnable (but just not actively
		 * running right now), it's preempted, and we should
		 * yield - it could be a while.
		 */
		if (unlikely(queued)) {
			set_current_state(TASK_UNINTERRUPTIBLE);
			/* 1 jiffiy? */
			schedule_timeout(1);
			continue;
		}

		/*
		 * Ahh, all good. It wasn't running, and it wasn't
		 * runnable, which means that it will never become
		 * running in the future either. We're all done!
		 */
		break;
	}

	return ncsw;
}

/***
 * kick_process - kick a running thread to enter/exit the kernel
 * @p: the to-be-kicked thread
 *
 * Cause a process which is running on another CPU to enter
 * kernel-mode, without any delay. (to get signals handled.)
 *
 * NOTE: this function doesn't have to take the runqueue lock,
 * because all it wants to ensure is that the remote task enters
 * the kernel. If the IPI races and the task has been migrated
 * to another CPU then no harm is done and the purpose has been
 * achieved as well.
 */
void kick_process(struct task_struct *p)
{
	int cpu;

	preempt_disable();
	cpu = task_cpu(p);
	if ((cpu != smp_processor_id()) && task_curr(p))
		smp_send_reschedule(cpu);
	preempt_enable();
}

/*
 * this_rq_lock - lock this runqueue and disable interrupts.
 */
static struct rq *this_rq_lock(void)
{
	struct rq *rq;

	local_irq_disable();
	rq = this_rq();
	spin_lock(&rq->lock);

	return rq;
}

/**
 * sys_sched_yield - yield the current processor to other threads.
 *
 * This function yields the current CPU to other tasks. If there are no
 * other threads running on this CPU then this function will return.
 *
 * Return: 0.
 */
SYSCALL_DEFINE0(sched_yield)
{
	struct rq *rq = this_rq_lock();

	BUG_ON(!current->sched_class->yield_task);
	current->sched_class->yield_task(rq);

	/*
	 * Since we are going to call schedule() anyway, there's
	 * no need to preempt or enable interrupts:
	 */
	spin_unlock(&rq->lock);
	preempt_enable_no_resched();

	schedule();

	return 0;
}

/*
 * Perform scheduler related setup for a newly forked process p.
 * p is forked by current.
 *
 * __sched_fork() is basic setup used by init_idle() too:
 */
static void __sched_fork(unsigned long clone_flags, struct task_struct *p)
{
	p->on_rq			= 0;

	p->se.on_rq			= 0;
	p->se.exec_start		= 0;
	p->se.sum_exec_runtime		= 0;
	p->se.prev_sum_exec_runtime	= 0;
	p->se.vruntime			= 0;

	INIT_LIST_HEAD(&p->rt.run_list);
	p->rt.timeout			= 0;
	p->rt.time_slice		= sysctl_sched_rr_timeslice;
}

/*
 * fork()-time setup:
 */
int setup_sched_fork(unsigned long clone_flags, struct task_struct *p)
{
	int cpu = get_cpu();

	__sched_fork(clone_flags, p);

	/*
	 * We mark the process as NEW here. This guarantees that
	 * nobody will actually run it, and a signal or other external
	 * event cannot wake it up and insert it on the runqueue either.
	 */
	p->state = TASK_NEW;

	/*
	 * Make sure we do not leak PI boosting priority to the child.
	 */
	p->prio = current->normal_prio;

	/*
	 * Revert to default priority/policy on fork if requested.
	 */
	if (unlikely(p->sched_reset_on_fork)) {
		if (task_has_rt_policy(p)) {
			p->policy = SCHED_NORMAL;
			p->static_prio = NICE_TO_PRIO(0);
			p->rt_priority = 0;
		} else if (PRIO_TO_NICE(p->static_prio) < 0)
			p->static_prio = NICE_TO_PRIO(0);

		p->prio = p->normal_prio = __normal_prio(p);
		set_load_weight(p);

		/*
		 * We don't need the reset flag anymore after the fork. It has
		 * fulfilled its duty:
		 */
		p->sched_reset_on_fork = 0;
	}

	if (rt_prio(p->prio))
		p->sched_class = &rt_sched_class;
	else {
		p->sched_class = &fair_sched_class;
		set_load_weight(p);
	}

	/*
	 * We're setting the cpu for the first time, we don't migrate,
	 * so use __set_task_cpu().
	 */
	__set_task_cpu(p, cpu);
	if (p->sched_class->task_fork)
		p->sched_class->task_fork(p);

#if defined(CONFIG_SMP)
	p->on_cpu = 0;
#endif

	put_cpu();
	return 0;
}

void set_task_comm(struct task_struct *tsk, const char *buf)
{
	task_lock(tsk);
	strlcpy(tsk->comm, buf, sizeof(tsk->comm));
	task_unlock(tsk);
}

char *get_task_comm(char *buf, struct task_struct *tsk)
{
	/* buf must be at least sizeof(tsk->comm) in size */
	task_lock(tsk);
	strncpy(buf, tsk->comm, sizeof(tsk->comm));
	task_unlock(tsk);
	return buf;
}

/**
 * sched_init_idle - set up an idle thread for a given CPU
 * @idle: task in question
 * @cpu: CPU the idle task belongs to
 */
void __init sched_init_idle(struct task_struct *idle, int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	unsigned long flags;

	spin_lock_irqsave(&idle->pi_lock, flags);
	spin_lock(&rq->lock);

	__sched_fork(0, idle);

	idle->state = TASK_RUNNING;
	idle->flags |= PF_IDLE;
	idle->se.exec_start = sched_clock();

#ifdef CONFIG_SMP
	set_cpus_allowed_common(idle, cpumask_of(cpu));
#endif

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
	spin_unlock(&rq->lock);
	spin_unlock_irqrestore(&idle->pi_lock, flags);

	/*
	 * Reset preempt count and in turn enable preemption
	 *
	 * It is safe to enable preemption during this time because
	 * we know nothing is going to happen to this CPU at this time.
	 */
	init_idle_preempt_count(idle, cpu);

	idle->sched_class = &idle_sched_class;

	sprintf(idle->comm, "swapper/%d", cpu);
}

void setup_init_idleclass(struct task_struct *idle)
{
	idle->sched_class = &idle_sched_class;
}

/*
 * Initialize the scheduler data structures
 * and enable the preemption in boot cpu 0.
 */
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
		atomic_set(&rq->nr_iowait, 0);

		init_cfs_rq(&rq->cfs);
		init_rt_rq(&rq->rt);
		init_dl_rq(&rq->dl);

#ifdef CONFIG_SMP
		rq->cpu = i;
		rq->online = 0;
#endif
	}

	/* At last, set cpu0's idle thread */
	sched_init_idle(current, smp_processor_id());

	scheduler_state = SCHED_UP;

	pr_info("Scheduler is up and running\n");
}

/*
 * Nice levels are multiplicative, with a gentle 10% change for every
 * nice level changed. I.e. when a CPU-bound task goes from nice 0 to
 * nice 1, it will get ~10% less CPU time than another CPU-bound task
 * that remained on nice 0.
 *
 * The "10% effect" is relative and cumulative: from _any_ nice level,
 * if you go up 1 level, it's -10% CPU usage, if you go down 1 level
 * it's +10% CPU usage. (to achieve that we use a multiplier of 1.25.
 * If a task goes up by ~10% and another task goes down by ~10% then
 * the relative distance between them is ~25%.)
 */
const int sched_prio_to_weight[40] = {
 /* -20 */     88761,     71755,     56483,     46273,     36291,
 /* -15 */     29154,     23254,     18705,     14949,     11916,
 /* -10 */      9548,      7620,      6100,      4904,      3906,
 /*  -5 */      3121,      2501,      1991,      1586,      1277,
 /*   0 */      1024,       820,       655,       526,       423,
 /*   5 */       335,       272,       215,       172,       137,
 /*  10 */       110,        87,        70,        56,        45,
 /*  15 */        36,        29,        23,        18,        15,
};

/*
 * Inverse (2^32/x) values of the sched_prio_to_weight[] array, precalculated.
 *
 * In cases where the weight does not change often, we can use the
 * precalculated inverse to speed up arithmetics by turning divisions
 * into multiplications:
 */
const u32 sched_prio_to_wmult[40] = {
 /* -20 */     48388,     59856,     76040,     92818,    118348,
 /* -15 */    147320,    184698,    229616,    287308,    360437,
 /* -10 */    449829,    563644,    704093,    875809,   1099582,
 /*  -5 */   1376151,   1717300,   2157191,   2708050,   3363326,
 /*   0 */   4194304,   5237765,   6557202,   8165337,  10153587,
 /*   5 */  12820798,  15790321,  19976592,  24970740,  31350126,
 /*  10 */  39045157,  49367440,  61356676,  76695844,  95443717,
 /*  15 */ 119304647, 148102320, 186737708, 238609294, 286331153,
};
