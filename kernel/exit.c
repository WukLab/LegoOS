/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/pid.h>
#include <lego/wait.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/syscalls.h>
#include <lego/profile.h>
#include <lego/debug_locks.h>

#include <processor/pcache.h>
#include <processor/processor.h>
#include <monitor/gpm_handler.h>

#ifdef CONFIG_DEBUG_EXIT
#define debug_exit(fmt, ...)					\
	pr_debug("%s() CPU:%d" fmt "\n",			\
		__func__, smp_processor_id(), __VA_ARGS__)
#else
#define debug_exit(fmt, ...)	do { } while (0)
#endif

/*
 * This function is called with tasklist_lock locked.
 * It will do necessary cleanup, a counterpart of fork.
 *
 * TODO:
 * Still need to detach/release PID
 */
static void __unhash_process(struct task_struct *p, bool group_dead)
{
	nr_threads--;

	if (group_dead) {
		list_del(&p->tasks);
		list_del_init(&p->sibling);
	}

	list_del(&p->thread_group);
	list_del(&p->thread_node);
}

/*
 * This function expects the tasklist_lock write-locked.
 */
static void __exit_signal(struct task_struct *tsk)
{
	struct signal_struct *sig = tsk->signal;
	bool group_dead = thread_group_leader(tsk);
	struct sighand_struct *sighand;

	sighand = tsk->sighand;
	spin_lock(&sighand->siglock);

	posix_cpu_timers_exit(tsk);
	if (group_dead) {
		posix_cpu_timers_exit_group(tsk);
	} else {
		/*
		 * This can only happen if the caller is de_thread().
		 * FIXME: this is the temporary hack, we should teach
		 * posix-cpu-timers to handle this case correctly.
		 */
		if (unlikely(has_group_leader_pid(tsk)))
			posix_cpu_timers_exit_group(tsk);

		/*
		 * If there is any task waiting for the group exit
		 * then notify it:
		 */
		if (sig->notify_count > 0 && !--sig->notify_count)
			wake_up_process(sig->group_exit_task);

		if (tsk == sig->curr_target)
			sig->curr_target = next_thread(tsk);
	}

	/*
	 * Accumulate here the counters for all threads as they die. We could
	 * skip the group leader because it is the last user of signal_struct,
	 * but we want to avoid the race with thread_group_cputime() which can
	 * see the empty ->thread_head list.
	 */
	spin_lock(&sig->stats_lock);
	sig->nvcsw += tsk->nvcsw;
	sig->nivcsw += tsk->nivcsw;
	sig->sum_sched_runtime += tsk->se.sum_exec_runtime;
	sig->nr_threads--;

	/* This is a very important cleanup function.. */
	__unhash_process(tsk, group_dead);

	spin_unlock(&sig->stats_lock);

	/*
	 * Do this under ->siglock, we can race with another thread
	 * doing sigqueue_free() if we have SIGQUEUE_PREALLOC signals.
	 */
	flush_sigqueue(&tsk->pending);
	tsk->sighand = NULL;
	spin_unlock(&sighand->siglock);

	__cleanup_sighand(sighand);
	clear_tsk_thread_flag(tsk, TIF_SIGPENDING);
	if (group_dead) {
		flush_sigqueue(&sig->shared_pending);
	}
}

void release_task(struct task_struct *p)
{
	struct task_struct *leader;
	int zap_leader;
repeat:

	spin_lock_irq(&tasklist_lock);
	__exit_signal(p);

	/*
	 * If we are the last non-leader member of the thread
	 * group, and the leader is zombie, then notify the
	 * group leader's parent process. (if it wants notification.)
	 */
	zap_leader = 0;
	leader = p->group_leader;
	if (leader != p && thread_group_empty(leader)
			&& leader->exit_state == EXIT_ZOMBIE) {
		/*
		 * If we were the last child thread and the leader has
		 * exited already, and the leader's parent ignores SIGCHLD,
		 * then we are the one who should release the leader.
		 */
		zap_leader = do_notify_parent(leader, leader->exit_signal);
		if (zap_leader)
			leader->exit_state = EXIT_DEAD;
	}

	spin_unlock_irq(&tasklist_lock);

	/*
	 * The task->usage is 2 when initalized.
	 * Thus when we drop 1 here, p will not be freed.
	 * The last free maybe performed by finish_task_switch().
	 */
	put_task_struct(p);

	p = leader;
	if (unlikely(zap_leader))
		goto repeat;
}

/*
 * XXX:
 * Lego does not have a nice terminal related thing now
 * Thus we won't have a signal stopped jobs.
 */
static bool has_stopped_jobs(pid_t pid)
{
	return false;
}

/*
 * Determine if a process group is "orphaned", according to the POSIX
 * definition in 2.2.2.52.  Orphaned process groups are not to be affected
 * by terminal-generated stop signals.  Newly orphaned process groups are
 * to receive a SIGHUP and a SIGCONT.
 *
 * Process groups that continue running even after the session leader has
 * terminated are marked as orphaned process groups.
 *
 * "I ask you, have you ever known what it is to be an orphan?"
 */
static int will_become_orphaned_pgrp(pid_t pid, struct task_struct *ignored_task)
{
	/*
	 * XXX:
	 * Since Lego does not support process group and session,
	 * each process is within its own group and session. Thus
	 * there should not be any orphaned pgrp in Lego.
	 */
	return 0;
}

int is_current_pgrp_orphaned(void)
{
	int retval;

	spin_lock(&tasklist_lock);
	retval = will_become_orphaned_pgrp(task_pgrp(current), NULL);
	spin_unlock(&tasklist_lock);

	return retval;
}

/*
 * Check to see if any process groups have become orphaned as
 * a result of our exiting, and if they have any stopped jobs,
 * send them a SIGHUP and then a SIGCONT. (POSIX 3.2.2.2)
 */
static void
kill_orphaned_pgrp(struct task_struct *tsk, struct task_struct *parent)
{
	pid_t pgrp = task_pgrp(tsk);
	struct task_struct *ignored_task = tsk;

	if (!parent)
		/* exit: our father is in a different pgrp than
		 * we are and we were the only connection outside.
		 */
		parent = tsk->real_parent;
	else
		/* reparent: our child is in a different pgrp than
		 * we are, and it was the only connection outside.
		 */
		ignored_task = NULL;

	if (task_pgrp(parent) != pgrp &&
	    task_session(parent) == task_session(tsk) &&
	    will_become_orphaned_pgrp(pgrp, ignored_task) &&
	    has_stopped_jobs(pgrp)) {
		WARN(1, "Should not happen!");
		__kill_pgrp_info(SIGHUP, SEND_SIG_PRIV, pgrp);
		__kill_pgrp_info(SIGCONT, SEND_SIG_PRIV, pgrp);
	}
}

static struct task_struct *find_alive_thread(struct task_struct *p)
{
	struct task_struct *t;

	for_each_thread(p, t) {
		if (!(t->flags & PF_EXITING))
			return t;
	}
	return NULL;
}

/*
 * Always use pid 1 as the child reaper
 * pid 1 must not exit.
 */
static struct task_struct *find_child_reaper(struct task_struct *father)
{
	struct task_struct *reaper;

	reaper = find_task_by_pid(1);
	if (likely(reaper != father))
		return reaper;
	BUG();
}

/*
 * When we die, we re-parent all our children, and try to:
 * 1. give them to another thread in our thread group, if such a member exists
 * 2. give it to the init process (PID 1) in our pid namespace
 */
static struct task_struct *find_new_reaper(struct task_struct *father,
					   struct task_struct *child_reaper)
{
	struct task_struct *thread;

	thread = find_alive_thread(father);
	if (thread)
		return thread;

	return child_reaper;
}

/*
 * Any that need to be release_task'd are put on the @dead list.
 */
static void reparent_leader(struct task_struct *father, struct task_struct *p,
				struct list_head *dead)
{
	if (unlikely(p->exit_state == EXIT_DEAD))
		return;

	/* We don't want people slaying init. */
	p->exit_signal = SIGCHLD;

	/* If it has exited notify the new parent about this child's death. */
	if (!p->ptrace &&
	    p->exit_state == EXIT_ZOMBIE && thread_group_empty(p)) {
		if (do_notify_parent(p, p->exit_signal)) {
			p->exit_state = EXIT_DEAD;
			list_add(&p->ptrace_entry, dead);
		}
	}

	kill_orphaned_pgrp(p, father);
}

/*
 * This does two things:
 *
 * A.  Make init inherit all the child processes
 * B.  Check to see if any process groups have become orphaned
 *	as a result of our exiting, and if they have any stopped
 *	jobs, send them a SIGHUP and then a SIGCONT.  (POSIX 3.2.2.2)
 *	(Should not happen in current Lego)
 */
static void forget_original_parent(struct task_struct *father,
				   struct list_head *dead)
{
	struct task_struct *p, *t, *reaper;

	/* Lego does not have ptrace now */
	BUG_ON(!list_empty(&father->ptraced));

	reaper = find_child_reaper(father);
	if (list_empty(&father->children))
		return;

	reaper = find_new_reaper(father, reaper);
	list_for_each_entry(p, &father->children, sibling) {
		for_each_thread(p, t) {
			t->real_parent = reaper;
			BUG_ON((!t->ptrace) != (t->parent == father));
			if (likely(!t->ptrace))
				t->parent = t->real_parent;
			if (t->pdeath_signal)
				group_send_sig_info(t->pdeath_signal,
						    SEND_SIG_NOINFO, t);
		}
		/*
		 * If this is a threaded reparent there is no need to
		 * notify anyone anything has happened.
		 */
		if (!same_thread_group(reaper, father))
			reparent_leader(father, p, dead);
	}
	list_splice_tail_init(&father->children, &reaper->children);
}

/*
 * Send signals to all our closest relatives so that they know
 * to properly mourn us..
 */
static void exit_notify(struct task_struct *tsk, int group_dead)
{
	bool autoreap;
	struct task_struct *p, *n;
	LIST_HEAD(dead);

	spin_lock_irq(&tasklist_lock);
	forget_original_parent(tsk, &dead);

	if (group_dead)
		kill_orphaned_pgrp(tsk->group_leader, NULL);

	if (unlikely(tsk->ptrace)) {
		int sig = thread_group_leader(tsk) &&
				thread_group_empty(tsk) &&
				!ptrace_reparented(tsk) ?
			tsk->exit_signal : SIGCHLD;
		autoreap = do_notify_parent(tsk, sig);
		WARN(1, "Should not happen.");
	} else if (thread_group_leader(tsk)) {
		autoreap = thread_group_empty(tsk) &&
			do_notify_parent(tsk, tsk->exit_signal);
	} else {
		autoreap = true;
	}

	tsk->exit_state = autoreap ? EXIT_DEAD : EXIT_ZOMBIE;
	if (tsk->exit_state == EXIT_DEAD)
		list_add(&tsk->ptrace_entry, &dead);

	/* mt-exec, de_thread() is waiting for group leader */
	if (unlikely(tsk->signal->notify_count < 0))
		wake_up_process(tsk->signal->group_exit_task);
	spin_unlock_irq(&tasklist_lock);

	list_for_each_entry_safe(p, n, &dead, ptrace_entry) {
		list_del_init(&p->ptrace_entry);
		release_task(p);
	}
}

static void exit_mm(struct task_struct *tsk)
{
	struct mm_struct *mm = tsk->mm;

	mm_release(tsk, mm);
	barrier();

	/* Wait for any pending pcache activities */
	pcache_thread_exit(tsk);

	/*
	 * Decrease mm_users by 1.
	 * Other threads within the group still hold the mm_users,
	 * so the mm will not be freed until the last thread exit.
	 *
	 * Also, we need do this before reset tsk->mm,
	 * because pcache_exit_process() still needs old_mm to clean up.
	 */
	mmput(mm);

	task_lock(tsk);
	tsk->mm = NULL;
	task_unlock(tsk);
}

void __noreturn do_exit(long code)
{
	struct task_struct *tsk = current;
	int group_dead;

	debug_exit("pid:%u,tgid:%u code:%#lx",
		current->pid, current->tgid, code);

	if (unlikely(!tsk->pid))
		panic("Attempted to kill the idle task!");

	if (unlikely(in_atomic())) {
		pr_info("note: %s[%d] exited with preempt_count %d\n",
			current->comm, current->pid, preempt_count());
		preempt_count_set(0);
	}

	/*
	 * If do_exit is called because this processes oopsed, it's possible
	 * that get_fs() was left as KERNEL_DS, so reset it to USER_DS before
	 * continuing. Amongst other possible reasons, this is to prevent
	 * mm_release()->clear_child_tid() from writing to a user-controlled
	 * kernel address.
	 */
	set_fs(USER_DS);

	/*
	 * We're taking recursive faults here in do_exit. Safest is to just
	 * leave this task alone and wait for reboot.
	 */
	if (unlikely(tsk->flags & PF_EXITING)) {
		pr_alert("Fixing recursive fault but reboot is needed!\n");
		/*
		 * We can do this unlocked here. The futex code uses
		 * this flag just to verify whether the pi state
		 * cleanup has been done or not. In the worst case it
		 * loops once more. We pretend that the cleanup was
		 * done as there is no way to return. Either the
		 * OWNER_DIED bit is set by now or we push the blocked
		 * task into the wait for ever nirwana as well.
		 */
		tsk->flags |= PF_EXITPIDONE;
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule();
	}

	exit_signals(tsk);  /* sets PF_EXITING */
	/*
	 * Ensure that all new tsk->pi_lock acquisitions must observe
	 * PF_EXITING. Serializes against futex.c:attach_to_pi_owner().
	 */
	smp_mb();

	{
		unsigned long start_ns = sched_clock();

		while (spin_is_locked(&tsk->pi_lock)) {
			if (sched_clock() - start_ns > 5 * NSEC_PER_SEC) {
				WARN_ON_ONCE(1);
				break;
			}
			continue;
		}
	}

	if (unlikely(in_atomic())) {
		pr_info("note: %s[%d] exited with preempt_count %d\n",
			current->comm, current->pid,
			preempt_count());
		preempt_count_set(0);
	}

	group_dead = atomic_dec_and_test(&tsk->signal->live);
	if (group_dead) {
		/* Cancel timers etc. */
		exit_itimers(tsk->signal);

#if 0
		exit_processor_strace(tsk);
		print_profile_heatmap_nr(10);
		print_profile_points();
		print_pcache_events();
#endif

#ifdef CONFIG_GPM
		report_proc_exit(code);
#endif
	}

	tsk->exit_code = code;
	exit_mm(tsk);
	exit_files(tsk);
	exit_thread(tsk);

	/*
	 * notify various parties about our death
	 * such as parents sleeping on wait4()
	 */
	exit_notify(tsk, group_dead);

	/* Make sure we are holding no locks */
	debug_check_no_locks_held();

	/* Now, time to say goodbye. */
	preempt_disable();
	do_task_dead();
}

/*
 * Take down every thread in the group.
 * This is called by fatal signals as well as by sys_exit_group (below).
 */
void do_group_exit(int exit_code)
{
	struct signal_struct *sig = current->signal;

	debug_exit("pid:%u,tgid:%u exit_code:%#x",
		current->pid, current->tgid, exit_code);

	BUG_ON(exit_code & 0x80); /* core dumps don't get here */

	if (signal_group_exit(sig))
		exit_code = sig->group_exit_code;
	else if (!thread_group_empty(current)) {
		struct sighand_struct *const sighand = current->sighand;

		spin_lock_irq(&sighand->siglock);
		if (signal_group_exit(sig))
			/* Another thread got here before we took the lock.  */
			exit_code = sig->group_exit_code;
		else {
			sig->group_exit_code = exit_code;
			sig->flags = SIGNAL_GROUP_EXIT;
			zap_other_threads(current);
		}
		spin_unlock_irq(&sighand->siglock);
	}

	do_exit(exit_code);

	/* NOTREACHED */
	BUG();
}

void __wake_up_parent(struct task_struct *p, struct task_struct *parent)
{
	__wake_up_sync_key(&parent->signal->wait_chldexit,
				TASK_INTERRUPTIBLE, 1, p);
}

SYSCALL_DEFINE1(exit, int, error_code)
{
	syscall_enter("error_code: %d\n", error_code);

	do_exit((error_code & 0xff) << 8);

	/* NOTREACHED */
	BUG();
	return 0;
}

/*
 * this kills every thread in the thread group. Note that any externally
 * wait4()-ing process will get the correct exit code - even if this
 * thread is not the thread group leader.
 */
SYSCALL_DEFINE1(exit_group, int, error_code)
{
	syscall_enter("error_code: %d\n", error_code);

	do_group_exit((error_code & 0xff) << 8);

	/* NOTREACHED */
	BUG();
	return 0;
}
