/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/time.h>
#include <lego/wait.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/waitpid.h>
#include <lego/syscalls.h>
#include <lego/debug_locks.h>

struct wait_opts {
	enum pid_type		wo_type;
	int			wo_flags;
	pid_t			wo_pid;

	struct siginfo __user	*wo_info;
	int __user		*wo_stat;
	struct rusage __user	*wo_rusage;

	wait_queue_t		child_wait;
	int			notask_error;
};

static inline pid_t task_pid_type(struct task_struct *task, enum pid_type type)
{
	/*
	 * Otherwise it is PGID.
	 * In Lego, we treat each process is in its own process group
	 * thus just return group_leader's pid
	 */
	if (type != PIDTYPE_PID)
		task = task->group_leader;
	return task->pid;
}

static int eligible_pid(struct wait_opts *wo, struct task_struct *p)
{
	return	wo->wo_type == PIDTYPE_MAX ||
		task_pid_type(p, wo->wo_type) == wo->wo_pid;
}

static int
eligible_child(struct wait_opts *wo, bool ptrace, struct task_struct *p)
{
	if (!eligible_pid(wo, p))
		return 0;

	/*
	 * Wait for all children (clone and not) if __WALL is set or
	 * if it is traced by us.
	 */
	if (ptrace || (wo->wo_flags & __WALL))
		return 1;

	/*
	 * Otherwise, wait for clone children *only* if __WCLONE is set;
	 * otherwise, wait for non-clone children *only*.
	 *
	 * Note: a "clone" child here is one that reports to its parent
	 * using a signal other than SIGCHLD, or a non-leader thread which
	 * we can only see if it is traced by us.
	 */
	if ((p->exit_signal != SIGCHLD) ^ !!(wo->wo_flags & __WCLONE))
		return 0;

	return 1;
}

static int wait_noreap_copyout(struct wait_opts *wo, struct task_struct *p,
				pid_t pid, uid_t uid, int why, int status)
{
	struct siginfo __user *infop;
	int retval = wo->wo_rusage
		? getrusage(p, RUSAGE_BOTH, wo->wo_rusage) : 0;

	put_task_struct(p);
	infop = wo->wo_info;
	if (infop) {
		if (!retval)
			retval = put_user(SIGCHLD, &infop->si_signo);
		if (!retval)
			retval = put_user(0, &infop->si_errno);
		if (!retval)
			retval = put_user((short)why, &infop->si_code);
		if (!retval)
			retval = put_user(pid, &infop->si_pid);
		if (!retval)
			retval = put_user(uid, &infop->si_uid);
		if (!retval)
			retval = put_user(status, &infop->si_status);
	}
	if (!retval)
		retval = pid;
	return retval;
}

/*
 * Handle sys_wait4 work for one task in state EXIT_ZOMBIE.  We hold
 * read_lock(&tasklist_lock) on entry.  If we return zero, we still hold
 * the lock and this task is uninteresting.  If we return nonzero, we have
 * released the lock and the system call should return.
 */
static int wait_task_zombie(struct wait_opts *wo, struct task_struct *p)
{
	int state, retval, status;
	pid_t pid = p->pid;
	uid_t uid = p->cred->uid;
	struct siginfo __user *infop;

	if (!likely(wo->wo_flags & WEXITED))
		return 0;

	if (unlikely(wo->wo_flags & WNOWAIT)) {
		int exit_code = p->exit_code;
		int why;

		get_task_struct(p);
		spin_unlock(&tasklist_lock);

		if ((exit_code & 0x7f) == 0) {
			why = CLD_EXITED;
			status = exit_code >> 8;
		} else {
			why = (exit_code & 0x80) ? CLD_DUMPED : CLD_KILLED;
			status = exit_code & 0x7f;
		}
		return wait_noreap_copyout(wo, p, pid, uid, why, status);
	}
	/*
	 * Move the task's state to DEAD/TRACE, only one thread can do this.
	 */
	state = (ptrace_reparented(p) && thread_group_leader(p)) ?
		EXIT_TRACE : EXIT_DEAD;
	if (cmpxchg(&p->exit_state, EXIT_ZOMBIE, state) != EXIT_ZOMBIE)
		return 0;
	/*
	 * We own this thread, nobody else can reap it.
	 */
	spin_unlock(&tasklist_lock);

	/*
	 * Check thread_group_leader() to exclude the traced sub-threads.
	 */
	if (state == EXIT_DEAD && thread_group_leader(p)) {
		struct signal_struct *sig = p->signal;
		struct signal_struct *psig = current->signal;
		unsigned long maxrss;
		cputime_t tgutime, tgstime;

		/*
		 * The resource counters for the group leader are in its
		 * own task_struct.  Those for dead threads in the group
		 * are in its signal_struct, as are those for the child
		 * processes it has previously reaped.  All these
		 * accumulate in the parent's signal_struct c* fields.
		 *
		 * We don't bother to take a lock here to protect these
		 * p->signal fields because the whole thread group is dead
		 * and nobody can change them.
		 *
		 * psig->stats_lock also protects us from our sub-theads
		 * which can reap other children at the same time. Until
		 * we change k_getrusage()-like users to rely on this lock
		 * we have to take ->siglock as well.
		 *
		 * We use thread_group_cputime_adjusted() to get times for
		 * the thread group, which consolidates times for all threads
		 * in the group including the group leader.
		 */
		spin_lock_irq(&current->sighand->siglock);
		spin_lock(&psig->stats_lock);
		psig->cutime += tgutime + sig->cutime;
		psig->cstime += tgstime + sig->cstime;
		psig->cgtime += sig->gtime + sig->cgtime;
		psig->cnvcsw +=
			p->nvcsw + sig->nvcsw + sig->cnvcsw;
		psig->cnivcsw +=
			p->nivcsw + sig->nivcsw + sig->cnivcsw;
		maxrss = max(sig->maxrss, sig->cmaxrss);
		if (psig->cmaxrss < maxrss)
			psig->cmaxrss = maxrss;
		spin_unlock(&psig->stats_lock);
		spin_unlock_irq(&current->sighand->siglock);
	}

	retval = wo->wo_rusage
		? getrusage(p, RUSAGE_BOTH, wo->wo_rusage) : 0;
	status = (p->signal->flags & SIGNAL_GROUP_EXIT)
		? p->signal->group_exit_code : p->exit_code;
	if (!retval && wo->wo_stat)
		retval = put_user(status, wo->wo_stat);

	infop = wo->wo_info;
	if (!retval && infop)
		retval = put_user(SIGCHLD, &infop->si_signo);
	if (!retval && infop)
		retval = put_user(0, &infop->si_errno);
	if (!retval && infop) {
		int why;

		if ((status & 0x7f) == 0) {
			why = CLD_EXITED;
			status >>= 8;
		} else {
			why = (status & 0x80) ? CLD_DUMPED : CLD_KILLED;
			status &= 0x7f;
		}
		retval = put_user((short)why, &infop->si_code);
		if (!retval)
			retval = put_user(status, &infop->si_status);
	}
	if (!retval && infop)
		retval = put_user(pid, &infop->si_pid);
	if (!retval && infop)
		retval = put_user(uid, &infop->si_uid);
	if (!retval)
		retval = pid;

	if (state == EXIT_TRACE) {
		unsigned long flags;

		spin_lock_irqsave(&tasklist_lock, flags);

		/* If parent wants a zombie, don't release it now */
		state = EXIT_ZOMBIE;
		if (do_notify_parent(p, p->exit_signal))
			state = EXIT_DEAD;
		p->exit_state = state;
		spin_unlock_irqrestore(&tasklist_lock, flags);
	}
	if (state == EXIT_DEAD)
		release_task(p);

	return retval;
}

static int *task_stopped_code(struct task_struct *p, bool ptrace)
{
	if (ptrace) {
		if (task_is_traced(p) && !(p->jobctl & JOBCTL_LISTENING))
			return &p->exit_code;
	} else {
		if (p->signal->flags & SIGNAL_STOP_STOPPED)
			return &p->signal->group_exit_code;
	}
	return NULL;
}

/**
 * wait_task_stopped - Wait for %TASK_STOPPED or %TASK_TRACED
 * @wo: wait options
 * @ptrace: is the wait for ptrace
 * @p: task to wait for
 *
 * Handle sys_wait4() work for %p in state %TASK_STOPPED or %TASK_TRACED.
 *
 * CONTEXT:
 * read_lock(&tasklist_lock), which is released if return value is
 * non-zero.  Also, grabs and releases @p->sighand->siglock.
 *
 * RETURNS:
 * 0 if wait condition didn't exist and search for other wait conditions
 * should continue.  Non-zero return, -errno on failure and @p's pid on
 * success, implies that tasklist_lock is released and wait condition
 * search should terminate.
 */
static int wait_task_stopped(struct wait_opts *wo,
				int ptrace, struct task_struct *p)
{
	struct siginfo __user *infop;
	int retval, exit_code, *p_code, why;
	uid_t uid = 0; /* unneeded, required by compiler */
	pid_t pid;

	/*
	 * Traditionally we see ptrace'd stopped tasks regardless of options.
	 */
	if (!ptrace && !(wo->wo_flags & WUNTRACED))
		return 0;

	if (!task_stopped_code(p, ptrace))
		return 0;

	exit_code = 0;
	spin_lock_irq(&p->sighand->siglock);

	p_code = task_stopped_code(p, ptrace);
	if (unlikely(!p_code))
		goto unlock_sig;

	exit_code = *p_code;
	if (!exit_code)
		goto unlock_sig;

	if (!unlikely(wo->wo_flags & WNOWAIT))
		*p_code = 0;

	uid = p->cred->uid;
unlock_sig:
	spin_unlock_irq(&p->sighand->siglock);
	if (!exit_code)
		return 0;

	/*
	 * Now we are pretty sure this task is interesting.
	 * Make sure it doesn't get reaped out from under us while we
	 * give up the lock and then examine it below.  We don't want to
	 * keep holding onto the tasklist_lock while we call getrusage and
	 * possibly take page faults for user memory.
	 */
	get_task_struct(p);
	pid = p->pid;
	why = ptrace ? CLD_TRAPPED : CLD_STOPPED;
	spin_unlock(&tasklist_lock);

	if (unlikely(wo->wo_flags & WNOWAIT))
		return wait_noreap_copyout(wo, p, pid, uid, why, exit_code);

	retval = wo->wo_rusage
		? getrusage(p, RUSAGE_BOTH, wo->wo_rusage) : 0;
	if (!retval && wo->wo_stat)
		retval = put_user((exit_code << 8) | 0x7f, wo->wo_stat);

	infop = wo->wo_info;
	if (!retval && infop)
		retval = put_user(SIGCHLD, &infop->si_signo);
	if (!retval && infop)
		retval = put_user(0, &infop->si_errno);
	if (!retval && infop)
		retval = put_user((short)why, &infop->si_code);
	if (!retval && infop)
		retval = put_user(exit_code, &infop->si_status);
	if (!retval && infop)
		retval = put_user(pid, &infop->si_pid);
	if (!retval && infop)
		retval = put_user(uid, &infop->si_uid);
	if (!retval)
		retval = pid;
	put_task_struct(p);

	BUG_ON(!retval);
	return retval;
}

/*
 * Handle do_wait work for one task in a live, non-stopped state.
 * read_lock(&tasklist_lock) on entry.  If we return zero, we still hold
 * the lock and this task is uninteresting.  If we return nonzero, we have
 * released the lock and the system call should return.
 */
static int wait_task_continued(struct wait_opts *wo, struct task_struct *p)
{
	int retval;
	pid_t pid;
	uid_t uid;

	if (!unlikely(wo->wo_flags & WCONTINUED))
		return 0;

	if (!(p->signal->flags & SIGNAL_STOP_CONTINUED))
		return 0;

	spin_lock_irq(&p->sighand->siglock);
	/* Re-check with the lock held.  */
	if (!(p->signal->flags & SIGNAL_STOP_CONTINUED)) {
		spin_unlock_irq(&p->sighand->siglock);
		return 0;
	}
	if (!unlikely(wo->wo_flags & WNOWAIT))
		p->signal->flags &= ~SIGNAL_STOP_CONTINUED;
	uid = p->cred->uid;
	spin_unlock_irq(&p->sighand->siglock);

	pid = p->pid;
	get_task_struct(p);
	spin_unlock(&tasklist_lock);

	if (!wo->wo_info) {
		retval = wo->wo_rusage
			? getrusage(p, RUSAGE_BOTH, wo->wo_rusage) : 0;
		put_task_struct(p);
		if (!retval && wo->wo_stat)
			retval = put_user(0xffff, wo->wo_stat);
		if (!retval)
			retval = pid;
	} else {
		retval = wait_noreap_copyout(wo, p, pid, uid,
					     CLD_CONTINUED, SIGCONT);
		BUG_ON(retval == 0);
	}

	return retval;
}

/*
 * Consider @p for a wait by @parent.
 *
 * -ECHILD should be in ->notask_error before the first call.
 * Returns nonzero for a final return, when we have unlocked tasklist_lock.
 * Returns zero if the search for a child should continue;
 * then ->notask_error is 0 if @p is an eligible child,
 * or another error from security_task_wait(), or still -ECHILD.
 */
static int wait_consider_task(struct wait_opts *wo, int ptrace,
				struct task_struct *p)
{
	/*
	 * We can race with wait_task_zombie() from another thread.
	 * Ensure that EXIT_ZOMBIE -> EXIT_DEAD/EXIT_TRACE transition
	 * can't confuse the checks below.
	 */
	int exit_state = ACCESS_ONCE(p->exit_state);
	int ret;

	if (unlikely(exit_state == EXIT_DEAD))
		return 0;

	ret = eligible_child(wo, ptrace, p);
	if (!ret)
		return ret;

	if (unlikely(exit_state == EXIT_TRACE)) {
		/*
		 * ptrace == 0 means we are the natural parent. In this case
		 * we should clear notask_error, debugger will notify us.
		 */
		if (likely(!ptrace))
			wo->notask_error = 0;
		return 0;
	}

	if (likely(!ptrace) && unlikely(p->ptrace)) {
		/*
		 * If it is traced by its real parent's group, just pretend
		 * the caller is ptrace_do_wait() and reap this child if it
		 * is zombie.
		 *
		 * This also hides group stop state from real parent; otherwise
		 * a single stop can be reported twice as group and ptrace stop.
		 * If a ptracer wants to distinguish these two events for its
		 * own children it should create a separate process which takes
		 * the role of real parent.
		 */
		if (!ptrace_reparented(p))
			ptrace = 1;
	}

	/* slay zombie? */
	if (exit_state == EXIT_ZOMBIE) {
		/* we don't reap group leaders with subthreads */
		if (!delay_group_leader(p)) {
			/*
			 * A zombie ptracee is only visible to its ptracer.
			 * Notification and reaping will be cascaded to the
			 * real parent when the ptracer detaches.
			 */
			if (unlikely(ptrace) || likely(!p->ptrace))
				return wait_task_zombie(wo, p);
		}

		/*
		 * Allow access to stopped/continued state via zombie by
		 * falling through.  Clearing of notask_error is complex.
		 *
		 * When !@ptrace:
		 *
		 * If WEXITED is set, notask_error should naturally be
		 * cleared.  If not, subset of WSTOPPED|WCONTINUED is set,
		 * so, if there are live subthreads, there are events to
		 * wait for.  If all subthreads are dead, it's still safe
		 * to clear - this function will be called again in finite
		 * amount time once all the subthreads are released and
		 * will then return without clearing.
		 *
		 * When @ptrace:
		 *
		 * Stopped state is per-task and thus can't change once the
		 * target task dies.  Only continued and exited can happen.
		 * Clear notask_error if WCONTINUED | WEXITED.
		 */
		if (likely(!ptrace) || (wo->wo_flags & (WCONTINUED | WEXITED)))
			wo->notask_error = 0;
	} else {
		/*
		 * @p is alive and it's gonna stop, continue or exit, so
		 * there always is something to wait for.
		 */
		wo->notask_error = 0;
	}

	/*
	 * Wait for stopped.  Depending on @ptrace, different stopped state
	 * is used and the two don't interact with each other.
	 */
	ret = wait_task_stopped(wo, ptrace, p);
	if (ret)
		return ret;

	/*
	 * Wait for continued.  There's only one continued state and the
	 * ptracer can consume it which can confuse the real parent.  Don't
	 * use WCONTINUED from ptracer.  You don't need or want it.
	 */
	return wait_task_continued(wo, p);
}

/*
 * Do the work of do_wait() for one thread in the group, @tsk.
 *
 * -ECHILD should be in ->notask_error before the first call.
 * Returns nonzero for a final return, when we have unlocked tasklist_lock.
 * Returns zero if the search for a child should continue; then
 * ->notask_error is 0 if there were any eligible children,
 * or another error from security_task_wait(), or still -ECHILD.
 */
static int do_wait_thread(struct wait_opts *wo, struct task_struct *tsk)
{
	struct task_struct *p;

	list_for_each_entry(p, &tsk->children, sibling) {
		int ret = wait_consider_task(wo, 0, p);

		if (ret)
			return ret;
	}

	return 0;
}

static int child_wait_callback(wait_queue_t *wait, unsigned mode,
				int sync, void *key)
{
	struct wait_opts *wo = container_of(wait, struct wait_opts,
						child_wait);
	struct task_struct *p = key;

	if (!eligible_pid(wo, p))
		return 0;

	if ((wo->wo_flags & __WNOTHREAD) && wait->private != p->parent)
		return 0;

	return default_wake_function(wait, mode, sync, key);
}

static long do_wait(struct wait_opts *wo)
{
	struct task_struct *tsk;
	int retval;

	init_waitqueue_func_entry(&wo->child_wait, child_wait_callback);
	wo->child_wait.private = current;
	add_wait_queue(&current->signal->wait_chldexit, &wo->child_wait);
repeat:
	/*
	 * If there is nothing that can match our criteria, just get out.
	 * We will clear ->notask_error to zero if we see any child that
	 * might later match our criteria, even if we are not able to reap
	 * it yet.
	 */
	wo->notask_error = -ECHILD;
	if ((wo->wo_type < PIDTYPE_MAX) &&
	   (!wo->wo_pid))
		goto notask;

	set_current_state(TASK_INTERRUPTIBLE);
	spin_lock(&tasklist_lock);
	tsk = current;
	do {
		retval = do_wait_thread(wo, tsk);
		if (retval)
			goto end;

		if (wo->wo_flags & __WNOTHREAD)
			break;
	} while_each_thread(current, tsk);
	spin_unlock(&tasklist_lock);

notask:
	retval = wo->notask_error;
	if (!retval && !(wo->wo_flags & WNOHANG)) {
		retval = -ERESTARTSYS;
		if (!signal_pending(current)) {
			schedule();
			goto repeat;
		}
	}
end:
	__set_current_state(TASK_RUNNING);
	remove_wait_queue(&current->signal->wait_chldexit, &wo->child_wait);
	return retval;
}

SYSCALL_DEFINE5(waitid, int, which, pid_t, upid, struct siginfo __user *,
		infop, int, options, struct rusage __user *, ru)
{
	struct wait_opts wo;
	pid_t pid;
	enum pid_type type;
	long ret;

	if (options & ~(WNOHANG|WNOWAIT|WEXITED|WSTOPPED|WCONTINUED|
			__WNOTHREAD|__WCLONE|__WALL))
		return -EINVAL;
	if (!(options & (WEXITED|WSTOPPED|WCONTINUED)))
		return -EINVAL;

	switch (which) {
	case P_ALL:
		/* Wait for any child; id is ignored */
		type = PIDTYPE_MAX;
		break;
	case P_PID:
		/* Wait for the child whose process ID matches id */
		type = PIDTYPE_PID;
		if (upid <= 0)
			return -EINVAL;
		break;
	case P_PGID:
		/* Wait for any child whose process group ID matches id */
		type = PIDTYPE_PGID;
		if (upid <= 0)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	if (type < PIDTYPE_MAX)
		pid = upid;

	wo.wo_type	= type;
	wo.wo_pid	= pid;
	wo.wo_flags	= options;
	wo.wo_info	= infop;
	wo.wo_stat	= NULL;
	wo.wo_rusage	= ru;
	ret = do_wait(&wo);

	if (ret > 0) {
		ret = 0;
	} else if (infop) {
		/*
		 * For a WNOHANG return, clear out all the fields
		 * we would set so the user can easily tell the
		 * difference.
		 */
		if (!ret)
			ret = put_user(0, &infop->si_signo);
		if (!ret)
			ret = put_user(0, &infop->si_errno);
		if (!ret)
			ret = put_user(0, &infop->si_code);
		if (!ret)
			ret = put_user(0, &infop->si_pid);
		if (!ret)
			ret = put_user(0, &infop->si_uid);
		if (!ret)
			ret = put_user(0, &infop->si_status);
	}

	return ret;
}

SYSCALL_DEFINE4(wait4, pid_t, upid, int __user *, stat_addr,
		int, options, struct rusage __user *, ru)
{
	struct wait_opts wo;
	pid_t pid;
	enum pid_type type;
	long ret;

	if (options & ~(WNOHANG|WUNTRACED|WCONTINUED|
			__WNOTHREAD|__WCLONE|__WALL))
		return -EINVAL;

	if (upid == -1) {
		/*
		 * wait for any child process whose process group ID is
		 * equal to the absolute value of pid
		 */
		type = PIDTYPE_MAX;
	} else if (upid < 0) {
		/*
		 * wait for any child process
		 */
		type = PIDTYPE_PGID;
		pid = -upid;
	} else if (upid == 0) {
		/*
		 * wait for any child process whose process group ID is
		 * equal to that of the calling process
		 */
		type = PIDTYPE_PGID;
		pid = current->pid;
	} else {
		/*
		 * wait for the child whose process ID is equal to the
		 * value of pid
		 */
		type = PIDTYPE_PID;
		pid = upid;
	}

	wo.wo_type	= type;
	wo.wo_pid	= pid;
	wo.wo_flags	= options | WEXITED;
	wo.wo_info	= NULL;
	wo.wo_stat	= stat_addr;
	wo.wo_rusage	= ru;
	ret = do_wait(&wo);

	return ret;
}
