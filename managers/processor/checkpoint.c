/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/pid.h>
#include <lego/timer.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/syscalls.h>
#include <lego/spinlock.h>

#undef debug
#define debug(fmt,...) pr_info(fmt, ##__VA_ARGS__)

/* Timeout for waiting all threads reach to barrier */
unsigned long checkpoint_barrier_timeout_msec = 20 * MSEC_PER_SEC;

/*
 * Do the real work of checkpoint a whole thread-group
 * @p: thread group leader
 */
static void do_checkpoint_process(struct task_struct *p)
{
	msleep(3000);
}

static void wake_up_children(struct task_struct *p)
{
	struct task_struct *t;
	unsigned long flags;

	spin_lock_irqsave(&tasklist_lock, flags);
	for_each_thread(p, t) {
		/* group leader itself is running this */
		if (p == t)
			continue;
		if (!wake_up_state(t, TASK_CHECKPOINTING))
			WARN(1, "Fail to wake: %d-%d-state:%ld\n",
				t->pid, t->tgid, t->state);
	}
	spin_unlock_irqrestore(&tasklist_lock, flags);
}

int checkpoint_thread(struct task_struct *p)
{
	struct task_struct *leader;
	long saved_state = p->state;

	debug("%s(): tsk: %d-%d\n", FUNC, p->pid, p->tgid);

	leader = p->group_leader;
	atomic_inc(&leader->process_barrier);

	if (p != leader) {
		set_current_state(TASK_CHECKPOINTING);
		schedule();

		/* Restore saved task state before returning: */
		set_current_state(saved_state);
	} else {
		ktime_t start, end, elapsed;
		unsigned long timeout, elapsed_msecs;

		start = ktime_get_boottime();
		timeout = jiffies + msecs_to_jiffies(checkpoint_barrier_timeout_msec);

		while (atomic_read(&p->process_barrier) != p->signal->nr_threads) {
			cpu_relax();

			if (time_after(jiffies, timeout)) {
				WARN_ON(1);
			}
		}

		end = ktime_get_boottime();
		elapsed = ktime_sub(end, start);
		elapsed_msecs = ktime_to_ms(elapsed);
		debug("Leader wait on barrier for: %d.%3d seconds\n",
			elapsed_msecs / 1000, elapsed_msecs % 1000);

		do_checkpoint_process(p);
		wake_up_children(p);
	}

	clear_tsk_thread_flag(p, TIF_NEED_CHECKPOINT);
	return 0;
}

/**
 * Checkpoint a thread group that @p belongs to.
 * This function is lightweight: set NEED_CHECKPOINT and kick all
 * threads to run. The real dirty work is done by do_checkpoint_process().
 */
static int checkpoint_process(struct task_struct *p)
{
	struct task_struct *t;
	unsigned long flags;

	spin_lock_irqsave(&tasklist_lock, flags);
	for_each_thread(p, t) {
		debug("Set NEED_CHECKPOINT for tsk: %d-%d\n", t->pid, t->tgid);
		set_tsk_thread_flag(t, TIF_NEED_CHECKPOINT);

		if (!wake_up_state(t, TASK_ALL))
			kick_process(t);
	}
	spin_unlock_irqrestore(&tasklist_lock, flags);

	return 0;
}

SYSCALL_DEFINE1(checkpoint_process, pid_t, pid)
{
	struct task_struct *tsk;
	long ret = 0;

	syscall_enter("pid: %d\n", pid);

	tsk = find_task_by_pid(pid);
	if (!tsk) {
		ret = -ESRCH;
		goto out;
	}

	ret = checkpoint_process(tsk);
out:
	syscall_exit(ret);
	return ret;
}
