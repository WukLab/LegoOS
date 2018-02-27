/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "Chkpt: " fmt

#include <lego/pid.h>
#include <lego/timer.h>
#include <lego/ktime.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>
#include <lego/syscalls.h>
#include <lego/spinlock.h>
#include <lego/checkpoint.h>
#include <lego/timekeeping.h>

#include "internal.h"

/* Timeout for waiting all threads reach to barrier */
#ifdef CONFIG_DEBUG_CHECKPOINT
unsigned long __read_mostly checkpoint_barrier_timeout_msec = 5 * MSEC_PER_SEC;
#else
unsigned long __read_mostly checkpoint_barrier_timeout_msec = 500;
#endif

/* Timeout for the real work of checkpointing to remote */
unsigned long __read_mostly checkpoint_job_timeout_msec = 10 * MSEC_PER_SEC;

/* A list of pss on processor-manager */
static LIST_HEAD(pss_list);
static DEFINE_SPINLOCK(pss_lock);

void enqueue_pss(struct process_snapshot *pss)
{
	BUG_ON(!pss);
	spin_lock(&pss_lock);
	list_add_tail(&pss->list, &pss_list);
	spin_unlock(&pss_lock);
}

struct process_snapshot *dequeue_pss(void)
{
	struct process_snapshot *pss = NULL;

	spin_lock(&pss_lock);
	if (!list_empty(&pss_list)) {
		pss = list_entry(pss_list.next, struct process_snapshot, list);
		list_del_init(&pss->list);
	}
	spin_unlock(&pss_lock);

	return pss;
}

#ifdef CONFIG_DEBUG_CHECKPOINT
static void paranoid_state_check(struct task_struct *leader)
{
	struct task_struct *t;
	unsigned long flags;

	/*
	 * Still need lock here in case there
	 * are someone skipping underneath. After all,
	 * you are very paranoid if you reach here:
	 */
	spin_lock_irqsave(&tasklist_lock, flags);
	for_each_thread(leader, t) {
		/* group leader itself is running this */
		if (leader == t)
			continue;
		if (unlikely(t->state != TASK_CHECKPOINTING))
			pr_info("BUG: t->state: %ld, t->pid: %d\n",
				t->state, t->pid);
	}
	spin_unlock_irqrestore(&tasklist_lock, flags);
}
#else
static inline void paranoid_state_check(struct task_struct *leader) { }
#endif

/*
 * Do the real work of checkpoint a whole thread-group
 * @p: thread group leader
 */
static int __do_checkpoint_process(struct task_struct *leader)
{
	struct task_struct *t;
	struct process_snapshot *pss;
	struct ss_task_struct *ss_tasks, *ss_task;
	int ret = 0, i = 0;

	paranoid_state_check(leader);

	pss = kmalloc(sizeof(*pss), GFP_KERNEL);
	if (!pss)
		return -ENOMEM;

	pss->nr_tasks = leader->signal->nr_threads;
	ss_tasks = kmalloc(sizeof(*ss_tasks) * pss->nr_tasks, GFP_KERNEL);
	if (!ss_tasks) {
		kfree(pss);
		return -ENOMEM;
	}

	/*
	 * First save thread-group shared data
	 */

	pss->tasks = ss_tasks;
	memcpy(pss->comm, leader->comm, TASK_COMM_LEN);

	ret = save_open_files(leader, pss);
	if (ret)
		goto out;

	ret = save_signals(leader, pss);
	if (ret)
		goto revert_files;

	/*
	 * Then save per-thread data
	 */

	for_each_thread(leader, t) {
		ss_task = &ss_tasks[i++];

		ss_task->pid = t->pid;
		ss_task->set_child_tid = t->set_child_tid;
		ss_task->clear_child_tid = t->clear_child_tid;
		ss_task->sas_ss_sp = t->sas_ss_sp;
		ss_task->sas_ss_size = t->sas_ss_size;
		ss_task->sas_ss_flags = t->sas_ss_flags;

		save_thread_regs(t, ss_task);
	}

#ifdef CONFIG_DEBUG_CHECKPOINT
	dump_process_snapshot(pss, "Saver", 0);
#endif

	/*
	 * TODO:
	 * Send to memory
	 */

	enqueue_pss(pss);
	return 0;

revert_files:
	revert_save_open_files(leader, pss);
out:
	kfree(ss_tasks);
	kfree(pss);
	return ret;
}

static int do_checkpoint_process(struct task_struct *leader)
{
	int ret;

	preempt_disable();
	ret = __do_checkpoint_process(leader);
	preempt_enable_no_resched();

	restore_process_snapshot(dequeue_pss());
	return ret;
}

static void wake_up_thread_group(struct task_struct *leader)
{
	struct task_struct *t;
	unsigned long flags;

	spin_lock_irqsave(&tasklist_lock, flags);
	for_each_thread(leader, t) {
		/* group leader itself is running this */
		if (leader == t)
			continue;
		if (!wake_up_state(t, TASK_CHECKPOINTING))
			WARN(1, "Fail to wake: %d-%d-state:%ld\n",
				t->pid, t->tgid, t->state);
	}
	spin_unlock_irqrestore(&tasklist_lock, flags);
}

static void barrier_timeout_wakeup(struct task_struct *leader)
{
	struct task_struct *t;
	unsigned long flags;
	int i = 0;

	pr_err("Abort due to barrier timeout. Leader-PID: %d, nr_threads: %d "
		"barrier_timeout_msec: %lu\n", leader->pid, leader->signal->nr_threads,
		checkpoint_barrier_timeout_msec);

	spin_lock_irqsave(&tasklist_lock, flags);
	for_each_thread(leader, t) {
		pr_err("    Thread %d: pid=%d, state=%ld, TIF_NEED_CHECKPOINT: %d\n",
			i++, t->pid, t->state, test_tsk_need_checkpoint(t));

		wake_up_state(t, TASK_ALL);
	}
	spin_unlock_irqrestore(&tasklist_lock, flags);
}

/*
 * This function is ONLY called if the TIF_NEED_CHECKPOINT is set.
 * Someone has called sys_checkpoint_process() previously.
 *
 * We wait until the whole thread group reach here, then let the
 * thread group leader do the dirty work. Others will just sleep
 * until leader wake them up.
 */
int checkpoint_thread(struct task_struct *p)
{
	struct task_struct *leader;
	long saved_state = p->state;

	chk_debug("%s(): tsk: %d-%d\n", FUNC, p->pid, p->tgid);
	BUG_ON(!test_tsk_need_checkpoint(p));

	leader = p->group_leader;
	atomic_inc(&leader->pm_data.process_barrier);

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

		while (atomic_read(&p->pm_data.process_barrier) != p->signal->nr_threads) {
			/*
			 * Abort whole checkpointing, and
			 * wake all threads:
			 */
			if (time_after(jiffies, timeout)) {
				barrier_timeout_wakeup(p);
				goto after_timeout;
			}
		}

		end = ktime_get_boottime();
		elapsed = ktime_sub(end, start);
		elapsed_msecs = ktime_to_ms(elapsed);
		chk_debug("Barrier elapsed %lu.%3lu seconds\n",
			elapsed_msecs / 1000, elapsed_msecs % 1000);

		do_checkpoint_process(p);

		/* Wake all threads sleeping in TASK_CHECKPOINTING */
		wake_up_thread_group(p);

after_timeout:
		/* Reset barrier info for next run: */
		atomic_set(&p->pm_data.process_barrier, 0);
	}

	clear_tsk_thread_flag(p, TIF_NEED_CHECKPOINT);
	return 0;
}

static int checkpoint_process_internal(struct task_struct *p)
{
	struct task_struct *t;
	unsigned long flags;

	spin_lock_irqsave(&tasklist_lock, flags);
	for_each_thread(p, t) {
		chk_debug("Set NEED_CHECKPOINT for tsk: %d-%d\n", t->pid, t->tgid);
		set_tsk_thread_flag(t, TIF_NEED_CHECKPOINT);

		if (!wake_up_state(t, TASK_ALL))
			kick_process(t);
	}
	spin_unlock_irqrestore(&tasklist_lock, flags);

	return 0;
}

/**
 * Checkpoint a thread group, whose PID is @pid
 * This function is lightweight: set NEED_CHECKPOINT, kick all
 * threads to run, that is all. The real dirty work is done by
 * do_checkpoint_process() above.
 */
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

	ret = checkpoint_process_internal(tsk);
out:
	syscall_exit(ret);
	return ret;
}
