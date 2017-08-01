/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/init.h>
#include <lego/slab.h>
#include <lego/sched.h>
#include <lego/signal.h>
#include <lego/signalfd.h>
#include <lego/spinlock.h>
#include <lego/syscalls.h>
#include <lego/ktime.h>
#include <lego/pid.h>

int print_fatal_signals __read_mostly;
static int __init setup_print_fatal_signals(char *str)
{
	print_fatal_signals = 1;

	return 1;
}
__setup("print-fatal-signals=", setup_print_fatal_signals);

static void print_fatal_signal(int signr)
{
	struct pt_regs *regs = task_pt_regs(current);
	pr_info("potentially unexpected fatal signal %d.\n", signr);

	preempt_disable();
	show_regs(regs);
	preempt_enable();
}

/**
 * task_set_jobctl_pending - set jobctl pending bits
 * @task: target task
 * @mask: pending bits to set
 *
 * Clear @mask from @task->jobctl.  @mask must be subset of
 * %JOBCTL_PENDING_MASK | %JOBCTL_STOP_CONSUME | %JOBCTL_STOP_SIGMASK |
 * %JOBCTL_TRAPPING.  If stop signo is being set, the existing signo is
 * cleared.  If @task is already being killed or exiting, this function
 * becomes noop.
 *
 * CONTEXT:
 * Must be called with @task->sighand->siglock held.
 *
 * RETURNS:
 * %true if @mask is set, %false if made noop because @task was dying.
 */
bool task_set_jobctl_pending(struct task_struct *task, unsigned long mask)
{
	BUG_ON(mask & ~(JOBCTL_PENDING_MASK | JOBCTL_STOP_CONSUME |
			JOBCTL_STOP_SIGMASK | JOBCTL_TRAPPING));
	BUG_ON((mask & JOBCTL_TRAPPING) && !(mask & JOBCTL_PENDING_MASK));

	if (unlikely(fatal_signal_pending(task) || (task->flags & PF_EXITING)))
		return false;

	if (mask & JOBCTL_STOP_SIGMASK)
		task->jobctl &= ~JOBCTL_STOP_SIGMASK;

	task->jobctl |= mask;
	return true;
}

/**
 * task_clear_jobctl_trapping - clear jobctl trapping bit
 * @task: target task
 *
 * If JOBCTL_TRAPPING is set, a ptracer is waiting for us to enter TRACED.
 * Clear it and wake up the ptracer.  Note that we don't need any further
 * locking.  @task->siglock guarantees that @task->parent points to the
 * ptracer.
 *
 * CONTEXT:
 * Must be called with @task->sighand->siglock held.
 */
void task_clear_jobctl_trapping(struct task_struct *task)
{
	if (unlikely(task->jobctl & JOBCTL_TRAPPING)) {
		task->jobctl &= ~JOBCTL_TRAPPING;
		smp_mb();	/* advised by wake_up_bit() */
		wake_up_bit(&task->jobctl, JOBCTL_TRAPPING_BIT);
	}
}

/**
 * task_clear_jobctl_pending - clear jobctl pending bits
 * @task: target task
 * @mask: pending bits to clear
 *
 * Clear @mask from @task->jobctl.  @mask must be subset of
 * %JOBCTL_PENDING_MASK.  If %JOBCTL_STOP_PENDING is being cleared, other
 * STOP bits are cleared together.
 *
 * If clearing of @mask leaves no stop or trap pending, this function calls
 * task_clear_jobctl_trapping().
 *
 * CONTEXT:
 * Must be called with @task->sighand->siglock held.
 */
void task_clear_jobctl_pending(struct task_struct *task, unsigned long mask)
{
	BUG_ON(mask & ~JOBCTL_PENDING_MASK);

	if (mask & JOBCTL_STOP_PENDING)
		mask |= JOBCTL_STOP_CONSUME | JOBCTL_STOP_DEQUEUED;

	task->jobctl &= ~mask;

	if (!(task->jobctl & JOBCTL_PENDING_MASK))
		task_clear_jobctl_trapping(task);
}

static inline void print_dropped_signal(int sig)
{
	//static DEFINE_RATELIMIT_STATE(ratelimit_state, 5 * HZ, 10);

	if (!print_fatal_signals)
		return;

	//if (!__ratelimit(&ratelimit_state))
		return;

	pr_info("%s/%d: reached RLIMIT_SIGPENDING, dropped signal %d\n",
				current->comm, current->pid, sig);
}

/* x86-64 */
#define __ARCH_SI_PREAMBLE_SIZE	(4 * sizeof(int))
static inline void copy_siginfo(struct siginfo *to, struct siginfo *from)
{
	if (from->si_code < 0)
		memcpy(to, from, sizeof(*to));
	else
		/* _sigchld is currently the largest know union member */
		memcpy(to, from, __ARCH_SI_PREAMBLE_SIZE + sizeof(from->_sifields._sigchld));
}

/*
 * Re-calculate pending state from the set of locally pending
 * signals, globally pending signals, and blocked signals.
 */
static inline int has_pending_signals(sigset_t *signal, sigset_t *blocked)
{
	unsigned long ready;
	long i;

	switch (_NSIG_WORDS) {
	default:
		for (i = _NSIG_WORDS, ready = 0; --i >= 0 ;)
			ready |= signal->sig[i] &~ blocked->sig[i];
		break;

	case 4: ready  = signal->sig[3] &~ blocked->sig[3];
		ready |= signal->sig[2] &~ blocked->sig[2];
		ready |= signal->sig[1] &~ blocked->sig[1];
		ready |= signal->sig[0] &~ blocked->sig[0];
		break;

	case 2: ready  = signal->sig[1] &~ blocked->sig[1];
		ready |= signal->sig[0] &~ blocked->sig[0];
		break;

	case 1: ready  = signal->sig[0] &~ blocked->sig[0];
	}
	return ready !=	0;
}

#define PENDING(p,b) has_pending_signals(&(p)->signal, (b))

static int recalc_sigpending_tsk(struct task_struct *t)
{
	if ((t->jobctl & JOBCTL_PENDING_MASK) ||
	    PENDING(&t->pending, &t->blocked) ||
	    PENDING(&t->signal->shared_pending, &t->blocked)) {
		set_tsk_thread_flag(t, TIF_SIGPENDING);
		return 1;
	}
	/*
	 * We must never clear the flag in another thread, or in current
	 * when it's possible the current syscall is returning -ERESTART*.
	 * So we don't clear it here, and only callers who know they should do.
	 */
	return 0;
}

/*
 * After recalculating TIF_SIGPENDING, we need to make sure the task wakes up.
 * This is superfluous when called on current, the wakeup is a harmless no-op.
 */
void recalc_sigpending_and_wake(struct task_struct *t)
{
	if (recalc_sigpending_tsk(t))
		signal_wake_up(t, 0);
}

void recalc_sigpending(void)
{
	if (!recalc_sigpending_tsk(current))
		clear_thread_flag(TIF_SIGPENDING);

}

/*
 * Tell a process that it has a new active signal..
 *
 * NOTE! we rely on the previous spin_lock to
 * lock interrupts for us! We can only be called with
 * "siglock" held, and the local interrupt must
 * have been disabled when that got acquired!
 *
 * No need to set need_resched since signal event passing
 * goes through ->blocked
 */
void signal_wake_up_state(struct task_struct *t, unsigned int state)
{
	set_tsk_thread_flag(t, TIF_SIGPENDING);
	/*
	 * TASK_WAKEKILL also means wake it up in the stopped/traced/killable
	 * case. We don't check t->state here because there is a race with it
	 * executing another processor and just now entering stopped state.
	 * By using wake_up_state, we ensure the process will wake up and
	 * handle its death signal.
	 */
	if (!wake_up_state(t, state | TASK_INTERRUPTIBLE))
		kick_process(t);
}

static inline int legacy_queue(struct sigpending *signals, int sig)
{
	return (sig < SIGRTMIN) && sigismember(&signals->signal, sig);
}

static inline int is_si_special(const struct siginfo *info)
{
	return info <= SEND_SIG_FORCED;
}

/*
 * allocate a new signal queue record
 * - this may be called without locks if and only if t == current, otherwise an
 *   appropriate lock must be held to stop the target task from exiting
 */
static struct sigqueue *
__sigqueue_alloc(int sig, struct task_struct *t, gfp_t flags, int override_rlimit)
{
	struct sigqueue *q = NULL;

	if (override_rlimit)
		q = kmalloc(sizeof(*q), flags);
	else
		print_dropped_signal(sig);

	if (likely(!q)) {
		INIT_LIST_HEAD(&q->list);
		q->flags = 0;
	}
	return q;
}

static void __sigqueue_free(struct sigqueue *q)
{
	kfree(q);
}

/*
 * Test if P wants to take SIG.  After we've checked all threads with this,
 * it's equivalent to finding no threads not blocking SIG.  Any threads not
 * blocking SIG were ruled out because they are not running and already
 * have pending signals.  Such threads will dequeue from the shared queue
 * as soon as they're available, so putting the signal on the shared queue
 * will be equivalent to sending it to one such thread.
 */
static inline int wants_signal(int sig, struct task_struct *p)
{
	if (sigismember(&p->blocked, sig))
		return 0;
	if (p->flags & PF_EXITING)
		return 0;
	if (sig == SIGKILL)
		return 1;
	if (task_is_stopped_or_traced(p))
		return 0;
	return task_curr(p) || !signal_pending(p);
}

static void complete_signal(int sig, struct task_struct *p, int group)
{
	struct signal_struct *signal = p->signal;
	struct task_struct *t;

	/*
	 * Now find a thread we can wake up to take the signal off the queue.
	 *
	 * If the main thread wants the signal, it gets first crack.
	 * Probably the least surprising to the average bear.
	 */
	if (wants_signal(sig, p))
		t = p;
	else if (!group || thread_group_empty(p))
		/*
		 * There is just one thread and it does not need to be woken.
		 * It will dequeue unblocked signals before it runs again.
		 */
		return;
	else {
		/*
		 * Otherwise try to find a suitable thread.
		 */
		t = signal->curr_target;
		while (!wants_signal(sig, t)) {
			t = next_thread(t);
			if (t == signal->curr_target)
				/*
				 * No thread needs to be woken.
				 * Any eligible threads will see
				 * the signal in the queue soon.
				 */
				return;
		}
		signal->curr_target = t;
	}

	/*
	 * Found a killable thread.  If the signal will be fatal,
	 * then start taking the whole group down immediately.
	 */
	if (sig_fatal(p, sig) &&
	    !(signal->flags & (SIGNAL_UNKILLABLE | SIGNAL_GROUP_EXIT)) &&
	    !sigismember(&t->real_blocked, sig) &&
	    (sig == SIGKILL)) {
		/*
		 * This signal will be fatal to the whole group.
		 */
		if (!sig_kernel_coredump(sig)) {
	printk("find11 testingkill \n");
			/*
			 * Start a group exit and wake everybody up.
			 * This way we don't have other threads
			 * running and doing things after a slower
			 * thread has the fatal signal pending.
			 */
			signal->flags = SIGNAL_GROUP_EXIT;
			signal->group_exit_code = sig;
			signal->group_stop_count = 0;
			t = p;
			//task_lock(p);
			do {
	printk("find10 testingkill \n");
				task_clear_jobctl_pending(t, JOBCTL_PENDING_MASK);
				sigaddset(&t->pending.signal, SIGKILL);
				signal_wake_up(t, 1);
			} while_each_thread(p, t);
			//task_unlock(p);
			return;
		}
	}

	/*
	 * The signal is already in the shared-pending queue.
	 * Tell the chosen thread to wake up and dequeue it.
	 */
	signal_wake_up(t, sig == SIGKILL);
	return;
}

static int
send_signal(int sig, struct siginfo *info, struct task_struct *t, int group)
{
	struct sigpending *pending;
	struct sigqueue *q;
	int override_rlimit;
	int ret = 0;

	BUG_ON(!spin_is_locked(&t->sighand->siglock));

	pending = group ? &t->signal->shared_pending : &t->pending;

	if (legacy_queue(pending, sig))
		goto out;

	/*
	 * fast-pathed signals for kernel-internal things
	 * like SIGSTOP or SIGKILL.
	 */
	if (info == SEND_SIG_FORCED)
		goto out_set;

	/*
	 * Real-time signals must be queued if sent by sigqueue, or
	 * some other real-time mechanism.  It is implementation
	 * defined whether kill() does so.  We attempt to do so, on
	 * the principle of least surprise, but since kill is not
	 * allowed to fail with EAGAIN when low on memory we just
	 * make sure at least one signal gets delivered and don't
	 * pass on the info struct.
	 */
	if (sig < SIGRTMIN)
		override_rlimit = (is_si_special(info) || info->si_code >= 0);
	else
		override_rlimit = 0;

	q = __sigqueue_alloc(sig, t, GFP_ATOMIC, override_rlimit);
	if (q) {
		list_add_tail(&q->list, &pending->list);
		switch ((unsigned long) info) {
		case (unsigned long) SEND_SIG_NOINFO:
			q->info.si_signo = sig;
			q->info.si_errno = 0;
			q->info.si_code = SI_USER;
			q->info.si_pid = current->group_leader->pid;
			q->info.si_uid = 0;
			break;
		case (unsigned long) SEND_SIG_PRIV:
			q->info.si_signo = sig;
			q->info.si_errno = 0;
			q->info.si_code = SI_KERNEL;
			q->info.si_pid = 0;
			q->info.si_uid = 0;
			break;
		default:
			copy_siginfo(&q->info, info);
			break;
		}
	} else if (!is_si_special(info)) {
		if (sig >= SIGRTMIN && info->si_code != SI_USER) {
			/*
			 * Queue overflow, abort.  We may abort if the
			 * signal was rt and sent by user using something
			 * other than kill().
			 */
			ret = -EAGAIN;
			goto out;
		} else {
			/*
			 * This is a silent loss of information.  We still
			 * send the signal, but the *info bits are lost.
			 */
		}
	}

out_set:
	signalfd_notify(t, sig);
	sigaddset(&pending->signal, sig);
	complete_signal(sig, t, group);

out:
	return ret;
}

int
__group_send_sig_info(int sig, struct siginfo *info, struct task_struct *p)
{
	return send_signal(sig, info, p, 1);
}

static int
specific_send_sig_info(int sig, struct siginfo *info, struct task_struct *t)
{
	return send_signal(sig, info, t, 0);
}

/*
 * Force a signal that the process can't ignore: if necessary
 * we unblock the signal and change any SIG_IGN to SIG_DFL.
 *
 * Note: If we unblock the signal, we always reset it to SIG_DFL,
 * since we do not want to have a signal handler that was blocked
 * be invoked when user space had explicitly blocked it.
 *
 * We don't want to have recursive SIGSEGV's etc, for example,
 * that is why we also clear SIGNAL_UNKILLABLE.
 */
int force_sig_info(int sig, struct siginfo *info, struct task_struct *t)
{
	unsigned long flags;
	int ret, blocked, ignored;
	struct k_sigaction *action;

	spin_lock_irqsave(&t->sighand->siglock, flags);
	action = &t->sighand->action[sig - 1];
	ignored = (action->sa.sa_handler == SIG_IGN);
	blocked = sigismember(&t->blocked, sig);
	if (blocked || ignored) {
		action->sa.sa_handler = SIG_DFL;
		if (blocked) {
			sigdelset(&t->blocked, sig);
			recalc_sigpending_and_wake(t);
		}
	}
	if (action->sa.sa_handler == SIG_DFL)
		t->signal->flags &= ~SIGNAL_UNKILLABLE;
	ret = specific_send_sig_info(sig, info, t);
	spin_unlock_irqrestore(&t->sighand->siglock, flags);

	return ret;
}

void force_sig(int sig, struct task_struct *p)
{
	force_sig_info(sig, SEND_SIG_PRIV, p);
}

/*
 * When things go south during signal handling, we
 * will force a SIGSEGV. And if the signal that caused
 * the problem was already a SIGSEGV, we'll want to
 * make sure we don't even try to deliver the signal..
 */
int force_sigsegv(int sig, struct task_struct *p)
{
	if (sig == SIGSEGV) {
		unsigned long flags;
		spin_lock_irqsave(&p->sighand->siglock, flags);
		p->sighand->action[sig - 1].sa.sa_handler = SIG_DFL;
		spin_unlock_irqrestore(&p->sighand->siglock, flags);
	}
	force_sig(SIGSEGV, p);
	return 0;
}

void exit_signals(struct task_struct *tsk)
{
	/* TODO */
}

/*
 * It could be that complete_signal() picked us to notify about the
 * group-wide signal. Other threads should be notified now to take
 * the shared signals in @which since we will not.
 */
static void retarget_shared_pending(struct task_struct *tsk, sigset_t *which)
{
	sigset_t retarget;
	struct task_struct *t;

	sigandsets(&retarget, &tsk->signal->shared_pending.signal, which);
	if (sigisemptyset(&retarget))
		return;

	t = tsk;
	//task_lock(tsk);
	while_each_thread(tsk, t) {
		if (t->flags & PF_EXITING)
			continue;

		if (!has_pending_signals(&retarget, &t->blocked))
			continue;
		/* Remove the signals this thread can handle. */
		sigandsets(&retarget, &retarget, &t->blocked);

		if (!signal_pending(t))
			signal_wake_up(t, 0);

		if (sigisemptyset(&retarget))
			break;
	}
	//task_unlock(tsk);
}

static void __set_task_blocked(struct task_struct *tsk, const sigset_t *newset)
{
	if (signal_pending(tsk) && !thread_group_empty(tsk)) {
		sigset_t newblocked;
		/* A set of now blocked but previously unblocked signals. */
		sigandnsets(&newblocked, newset, &current->blocked);
		retarget_shared_pending(tsk, &newblocked);
	}
	tsk->blocked = *newset;
	recalc_sigpending();
}

void __set_current_blocked(const sigset_t *newset)
{
	struct task_struct *tsk = current;

	spin_lock_irq(&tsk->sighand->siglock);
	__set_task_blocked(tsk, newset);
	spin_unlock_irq(&tsk->sighand->siglock);
}

/**
 * set_current_blocked - change current->blocked mask
 * @newset: new mask
 *
 * It is wrong to change ->blocked directly, this helper should be used
 * to ensure the process can't miss a shared signal we are going to block.
 */
void set_current_blocked(sigset_t *newset)
{
	sigdelsetmask(newset, sigmask(SIGKILL) | sigmask(SIGSTOP));
	__set_current_blocked(newset);
}

static inline void task_cputime(struct task_struct *t,
				cputime_t *utime, cputime_t *stime)
{
	if (utime)
		*utime = t->utime;
	if (stime)
		*stime = t->stime;
}

/**
 * do_notify_parent_cldstop - notify parent of stopped/continued state change
 * @tsk: task reporting the state change
 * @for_ptracer: the notification is for ptracer
 * @why: CLD_{CONTINUED|STOPPED|TRAPPED} to report
 *
 * Notify @tsk's parent that the stopped/continued state has changed.  If
 * @for_ptracer is %false, @tsk's group leader notifies to its real parent.
 * If %true, @tsk reports to @tsk->parent which should be the ptracer.
 *
 * CONTEXT:
 * Must be called with tasklist_lock at least read locked.
 */
static void do_notify_parent_cldstop(struct task_struct *tsk,
				     bool for_ptracer, int why)
{
	struct siginfo info;
	unsigned long flags;
	struct task_struct *parent;
	struct sighand_struct *sighand;
	cputime_t utime, stime;

	if (for_ptracer) {
		parent = tsk->parent;
	} else {
		tsk = tsk->group_leader;
		parent = tsk->real_parent;
	}

	info.si_signo = SIGCHLD;
	info.si_errno = 0;
	info.si_pid = tsk->pid;

	task_cputime(tsk, &utime, &stime);
/*
	info.si_utime = cputime_to_clock_t(utime);
	info.si_stime = cputime_to_clock_t(stime);
*/
 	info.si_code = why;
 	switch (why) {
 	case CLD_CONTINUED:
 		info.si_status = SIGCONT;
 		break;
 	case CLD_STOPPED:
 		info.si_status = tsk->signal->group_exit_code & 0x7f;
 		break;
 	case CLD_TRAPPED:
 		info.si_status = tsk->exit_code & 0x7f;
 		break;
 	default:
 		BUG();
 	}

	sighand = parent->sighand;
	spin_lock_irqsave(&sighand->siglock, flags);
	if (sighand->action[SIGCHLD-1].sa.sa_handler != SIG_IGN &&
	    !(sighand->action[SIGCHLD-1].sa.sa_flags & SA_NOCLDSTOP))
		__group_send_sig_info(SIGCHLD, &info, parent);

	/*
	 * Even if SIGCHLD is not generated,
	 * we must wake up wait4 calls.
	 */
	__wake_up_parent(tsk, parent);
	spin_unlock_irqrestore(&sighand->siglock, flags);
}

/**
 * task_participate_group_stop - participate in a group stop
 * @task: task participating in a group stop
 *
 * @task has %JOBCTL_STOP_PENDING set and is participating in a group stop.
 * Group stop states are cleared and the group stop count is consumed if
 * %JOBCTL_STOP_CONSUME was set.  If the consumption completes the group
 * stop, the appropriate %SIGNAL_* flags are set.
 *
 * CONTEXT:
 * Must be called with @task->sighand->siglock held.
 *
 * RETURNS:
 * %true if group stop completion should be notified to the parent, %false
 * otherwise.
 */
static bool task_participate_group_stop(struct task_struct *task)
{
	struct signal_struct *sig = task->signal;
	bool consume = task->jobctl & JOBCTL_STOP_CONSUME;

	WARN_ON_ONCE(!(task->jobctl & JOBCTL_STOP_PENDING));

	task_clear_jobctl_pending(task, JOBCTL_STOP_PENDING);

	if (!consume)
		return false;

	if (!WARN_ON_ONCE(sig->group_stop_count == 0))
		sig->group_stop_count--;

	/*
	 * Tell the caller to notify completion iff we are entering into a
	 * fresh group stop.  Read comment in do_signal_stop() for details.
	 */
	if (!sig->group_stop_count && !(sig->flags & SIGNAL_STOP_STOPPED)) {
		sig->flags = (sig->flags & ~SIGNAL_STOP_MASK) | SIGNAL_STOP_STOPPED;
		return true;
	}
	return false;
}

/**
 * do_signal_stop - handle group stop for SIGSTOP and other stop signals
 * @signr: signr causing group stop if initiating
 *
 * If %JOBCTL_STOP_PENDING is not set yet, initiate group stop with @signr
 * and participate in it.  If already set, participate in the existing
 * group stop.  If participated in a group stop (and thus slept), %true is
 * returned with siglock released.
 *
 * If ptraced, this function doesn't handle stop itself.  Instead,
 * %JOBCTL_TRAP_STOP is scheduled and %false is returned with siglock
 * untouched.  The caller must ensure that INTERRUPT trap handling takes
 * places afterwards.
 *
 * CONTEXT:
 * Must be called with @current->sighand->siglock held, which is released
 * on %true return.
 *
 * RETURNS:
 * %false if group stop is already cancelled or ptrace trap is scheduled.
 * %true if participated in group stop.
 */
static bool do_signal_stop(int signr)
	__releases(&current->sighand->siglock)
{
	struct signal_struct *sig = current->signal;

	if (!(current->jobctl & JOBCTL_STOP_PENDING)) {
		unsigned long gstop = JOBCTL_STOP_PENDING | JOBCTL_STOP_CONSUME;
		struct task_struct *t;

		/* signr will be recorded in task->jobctl for retries */
		WARN_ON_ONCE(signr & ~JOBCTL_STOP_SIGMASK);

		if (!likely(current->jobctl & JOBCTL_STOP_DEQUEUED) ||
		    unlikely(signal_group_exit(sig)))
			return false;
		/*
		 * There is no group stop already in progress.  We must
		 * initiate one now.
		 *
		 * While ptraced, a task may be resumed while group stop is
		 * still in effect and then receive a stop signal and
		 * initiate another group stop.  This deviates from the
		 * usual behavior as two consecutive stop signals can't
		 * cause two group stops when !ptraced.  That is why we
		 * also check !task_is_stopped(t) below.
		 *
		 * The condition can be distinguished by testing whether
		 * SIGNAL_STOP_STOPPED is already set.  Don't generate
		 * group_exit_code in such case.
		 *
		 * This is not necessary for SIGNAL_STOP_CONTINUED because
		 * an intervening stop signal is required to cause two
		 * continued events regardless of ptrace.
		 */
		if (!(sig->flags & SIGNAL_STOP_STOPPED))
			sig->group_exit_code = signr;

		printk("testing9\n");
		sig->group_stop_count = 0;

		if (task_set_jobctl_pending(current, signr | gstop))
			sig->group_stop_count++;

		t = current;
		//task_lock(current);
		while_each_thread(current, t) {
			/*
			 * Setting state to TASK_STOPPED for a group
			 * stop is always done with the siglock held,
			 * so this check has no races.
			 */
			if (!task_is_stopped(t) &&
			    task_set_jobctl_pending(t, signr | gstop)) {
				sig->group_stop_count++;
				signal_wake_up(t, 0);
			}
		}
		//task_unlock(current);
		printk("testing10\n");
	}

	if (likely(!current->ptrace)) {
		int notify = 0;

		/*
		 * If there are no other threads in the group, or if there
		 * is a group stop in progress and we are the last to stop,
		 * report to the parent.
		 */
		if (task_participate_group_stop(current))
			notify = CLD_STOPPED;

		printk("notification state = %d\n", notify);
		__set_current_state(TASK_STOPPED);
		spin_unlock_irq(&current->sighand->siglock);

		/*
		 * Notify the parent of the group stop completion.  Because
		 * we're not holding either the siglock or tasklist_lock
		 * here, ptracer may attach inbetween; however, this is for
		 * group stop and should always be delivered to the real
		 * parent of the group leader.  The new ptracer will get
		 * its notification when this task transitions into
		 * TASK_TRACED.
		 */
		if (notify) {
			spin_lock(&tasklist_lock);
			do_notify_parent_cldstop(current, false, notify);
			spin_unlock(&tasklist_lock);
		}

		printk("testing11\n");
		/* Now we don't run again until woken by SIGCONT or SIGKILL */
		schedule();
		printk("testing13\n");
		return true;
	} else {
		/*
		 * While ptraced, group stop is handled by STOP trap.
		 * Schedule it and let the caller deal with it.
		 */
		task_set_jobctl_pending(current, JOBCTL_TRAP_STOP);
		return false;
	}
}

/**
 * do_jobctl_trap - take care of ptrace jobctl traps
 *
 * When PT_SEIZED, it's used for both group stop and explicit
 * SEIZE/INTERRUPT traps.  Both generate PTRACE_EVENT_STOP trap with
 * accompanying siginfo.  If stopped, lower eight bits of exit_code contain
 * the stop signal; otherwise, %SIGTRAP.
 *
 * When !PT_SEIZED, it's used only for group stop trap with stop signal
 * number as exit_code and no siginfo.
 *
 * CONTEXT:
 * Must be called with @current->sighand->siglock held, which may be
 * released and re-acquired before returning with intervening sleep.
 */
static void do_jobctl_trap(void)
{
	WARN_ON(1);
}

/* Given the mask, find the first available signal that should be serviced. */

#define SYNCHRONOUS_MASK \
	(sigmask(SIGSEGV) | sigmask(SIGBUS) | sigmask(SIGILL) | \
	 sigmask(SIGTRAP) | sigmask(SIGFPE) | sigmask(SIGSYS))

int next_signal(struct sigpending *pending, sigset_t *mask)
{
	unsigned long i, *s, *m, x;
	int sig = 0;

	s = pending->signal.sig;
	m = mask->sig;

	/*
	 * Handle the first word specially: it contains the
	 * synchronous signals that need to be dequeued first.
	 */
	x = *s &~ *m;
	if (x) {
		if (x & SYNCHRONOUS_MASK)
			x &= SYNCHRONOUS_MASK;
		sig = ffz(~x) + 1;
		return sig;
	}

	switch (_NSIG_WORDS) {
	default:
		for (i = 1; i < _NSIG_WORDS; ++i) {
			x = *++s &~ *++m;
			if (!x)
				continue;
			sig = ffz(~x) + i*_NSIG_BPW + 1;
			break;
		}
		break;

	case 2:
		x = s[1] &~ m[1];
		if (!x)
			break;
		sig = ffz(~x) + _NSIG_BPW + 1;
		break;

	case 1:
		/* Nothing to do */
		break;
	}

	return sig;
}

static void collect_signal(int sig, struct sigpending *list, siginfo_t *info)
{
	struct sigqueue *q, *first = NULL;

	/*
	 * Collect the siginfo appropriate to this signal.  Check if
	 * there is another siginfo for the same signal.
	*/
	printk("find4 testingkill \n");
	list_for_each_entry(q, &list->list, list) {
	printk("find7 testingkill \n");
		if (q->info.si_signo == sig) {
	printk("find8 testingkill \n");
			if (first)
				goto still_pending;
			first = q;
		}
	}

	printk("find3 testingkill \n");
	sigdelset(&list->signal, sig);

	if (first) {
still_pending:
	printk("find5 testingkill \n");
		list_del_init(&first->list);
		copy_siginfo(info, &first->info);
		__sigqueue_free(first);
	} else {
		/*
		 * Ok, it wasn't in the queue.  This must be
		 * a fast-pathed signal or we must have been
		 * out of queue space.  So zero out the info.
		 */
		info->si_signo = sig;
		info->si_errno = 0;
		info->si_code = SI_USER;
		info->si_pid = 0;
		info->si_uid = 0;
	}
	printk("find6 testingkill \n");
}

static int __dequeue_signal(struct sigpending *pending, sigset_t *mask,
			siginfo_t *info)
{
	int sig = next_signal(pending, mask);

	printk("find testingkill %d\n", sig);
	if (sig)
		collect_signal(sig, pending, info);
	return sig;
}

/*
 * Dequeue a signal and return the element to the caller, which is
 * expected to free it.
 *
 * All callers have to hold the siglock.
 */
int dequeue_signal(struct task_struct *tsk, sigset_t *mask, siginfo_t *info)
{
	int signr;

	/* We only dequeue private signals from ourselves,
	 * we don't let signalfd steal them
	 */
	printk("find2 testingkill\n");
	signr = __dequeue_signal(&tsk->pending, mask, info);
	if (!signr) {
		signr = __dequeue_signal(&tsk->signal->shared_pending,
					 mask, info);
		/*
		 * itimer signal ?
		 *
		 * itimers are process shared and we restart periodic
		 * itimers in the signal delivery path to prevent DoS
		 * attacks in the high resolution timer case. This is
		 * compliant with the old way of self-restarting
		 * itimers, as the SIGALRM is a legacy signal and only
		 * queued once. Changing the restart behaviour to
		 * restart the timer in the signal dequeue path is
		 * reducing the timer noise on heavy loaded !highres
		 * systems too.
		 */
		if (unlikely(signr == SIGALRM)) {
			WARN_ON(1);
		}
	}

	recalc_sigpending();
	if (!signr)
		return 0;

	if (unlikely(sig_kernel_stop(signr))) {
		/*
		 * Set a marker that we have dequeued a stop signal.  Our
		 * caller might release the siglock and then the pending
		 * stop signal it is about to process is no longer in the
		 * pending bitmasks, but must still be cleared by a SIGCONT
		 * (and overruled by a SIGKILL).  So those cases clear this
		 * shared flag after we've set it.  Note that this flag may
		 * remain set after the signal we return is ignored or
		 * handled.  That doesn't matter because its only purpose
		 * is to alert stop-signal processing code when another
		 * processor has come along and cleared the flag.
		 */
		current->jobctl |= JOBCTL_STOP_DEQUEUED;
	}
	if ((info->si_code & __SI_MASK) == __SI_TIMER && info->si_sys_private) {
		/*
		 * Release the siglock to ensure proper locking order
		 * of timer locks outside of siglocks.  Note, we leave
		 * irqs disabled here, since the posix-timers code is
		 * about to disable them again anyway.
		 */
		spin_unlock(&tsk->sighand->siglock);
		do_schedule_next_timer(info);
		spin_lock(&tsk->sighand->siglock);
	}
	return signr;
}

int get_signal(struct ksignal *ksig)
{
	struct sighand_struct *sighand = current->sighand;
	struct signal_struct *signal = current->signal;
	int signr;

relock:
	spin_lock_irq(&sighand->siglock);
	/*
	 * Every stopped thread goes here after wakeup. Check to see if
	 * we should notify the parent, prepare_signal(SIGCONT) encodes
	 * the CLD_ si_code into SIGNAL_CLD_MASK bits.
	 */
	if (unlikely(signal->flags & SIGNAL_CLD_MASK)) {
		int why;

		if (signal->flags & SIGNAL_CLD_CONTINUED)
			why = CLD_CONTINUED;
		else
			why = CLD_STOPPED;

		signal->flags &= ~SIGNAL_CLD_MASK;

		spin_unlock_irq(&sighand->siglock);

		/*
		 * Notify the parent that we're continuing.  This event is
		 * always per-process and doesn't make whole lot of sense
		 * for ptracers, who shouldn't consume the state via
		 * wait(2) either, but, for backward compatibility, notify
		 * the ptracer of the group leader too unless it's gonna be
		 * a duplicate.
		 */
		spin_lock(&tasklist_lock);
		do_notify_parent_cldstop(current, false, why);

		if (ptrace_reparented(current->group_leader))
			do_notify_parent_cldstop(current->group_leader,
						true, why);
		spin_unlock(&tasklist_lock);

		goto relock;
	}
	printk("find handler \n");

	for (;;) {
		struct k_sigaction *ka;

		if (unlikely(current->jobctl & JOBCTL_STOP_PENDING) &&
		    do_signal_stop(0))
			goto relock;

		if (unlikely(current->jobctl & JOBCTL_TRAP_MASK)) {
			do_jobctl_trap();
			spin_unlock_irq(&sighand->siglock);
			goto relock;
		}

		signr = dequeue_signal(current, &current->blocked, &ksig->info);
		
		printk("testing2 signal number, %d\n", signr);
		if (!signr)
			break; /* will return 0 */

		ka = &sighand->action[signr-1];

		if (ka->sa.sa_handler == SIG_IGN) /* Do nothing.  */
			continue;
		if (ka->sa.sa_handler != SIG_DFL) {
			/* Run the handler.  */
			ksig->ka = *ka;

			if (ka->sa.sa_flags & SA_ONESHOT)
				ka->sa.sa_handler = SIG_DFL;

			break; /* will return non-zero "signr" value */
		}

		/*
		 * Now we are doing the default action for this signal.
		 */
		if (sig_kernel_ignore(signr)) /* Default is nothing. */
			continue;

		/*
		 * Global init gets no signals it doesn't want.
		 * Container-init gets no signals it doesn't want from same
		 * container.
		 *
		 * Note that if global/container-init sees a sig_kernel_only()
		 * signal here, the signal must have been generated internally
		 * or must have come from an ancestor namespace. In either
		 * case, the signal cannot be dropped.
		 */
		if (unlikely(signal->flags & SIGNAL_UNKILLABLE) &&
				!sig_kernel_only(signr))
			continue;

		if (sig_kernel_stop(signr)) {
			/*
			 * The default action is to stop all threads in
			 * the thread group.  The job control signals
			 * do nothing in an orphaned pgrp, but SIGSTOP
			 * always works.  Note that siglock needs to be
			 * dropped during the call to is_orphaned_pgrp()
			 * because of lock ordering with tasklist_lock.
			 * This allows an intervening SIGCONT to be posted.
			 * We need to check for that and bail out if necessary.
			 */
		printk("testing8\n");
			if (signr != SIGSTOP) {
				spin_unlock_irq(&sighand->siglock);

				/* signals can be posted during this window */

				if (is_current_pgrp_orphaned())
					goto relock;

				spin_lock_irq(&sighand->siglock);
			}

			if (likely(do_signal_stop(ksig->info.si_signo))) {
				/* It released the siglock.  */
				goto relock;
			}

		printk("testing12\n");

			/*
			 * We didn't actually stop, due to a race
			 * with SIGCONT or something like that.
			 */
			continue;
		}

		spin_unlock_irq(&sighand->siglock);

		/*
		 * Anything else is fatal, maybe with a core dump.
		 */
		current->flags |= PF_SIGNALED;

		if (sig_kernel_coredump(signr)) {
			if (print_fatal_signals)
				print_fatal_signal(ksig->info.si_signo);
			/*
			 * If it was able to dump core, this kills all
			 * other threads in the group and synchronizes with
			 * their demise.  If we lost the race with another
			 * thread getting here, it set group_exit_code
			 * first and our do_group_exit call below will use
			 * that value and ignore the one we pass it.
			 */
			do_coredump(&ksig->info);
		}

		printk("testing6\n");
		/*
		 * Death signals, no core dump.
		 */
		do_group_exit(ksig->info.si_signo);
		/* NOTREACHED */
		
		printk("testing7\n");
	}
	spin_unlock_irq(&sighand->siglock);

	printk("testing3\n");
	ksig->sig = signr;
	return ksig->sig > 0;
}

/**
 * signal_delivered - 
 * @ksig:		kernel signal struct
 * @stepping:		nonzero if debugger single-step or block-step in use
 *
 * This function should be called when a signal has successfully been
 * delivered. It updates the blocked signals accordingly (@ksig->ka.sa.sa_mask
 * is always blocked, and the signal itself is blocked unless %SA_NODEFER
 * is set in @ksig->ka.sa.sa_flags.  Tracing is notified.
 */
static void signal_delivered(struct ksignal *ksig, int stepping)
{
	sigset_t blocked;

	/* A signal was successfully delivered, and the
	   saved sigmask was stored on the signal frame,
	   and will be restored by sigreturn.  So we can
	   simply clear the restore sigmask flag.  */
	clear_restore_sigmask();

	sigorsets(&blocked, &current->blocked, &ksig->ka.sa.sa_mask);
	if (!(ksig->ka.sa.sa_flags & SA_NODEFER))
		sigaddset(&blocked, ksig->sig);
	set_current_blocked(&blocked);
}

void signal_setup_done(int failed, struct ksignal *ksig, int stepping)
{
	if (failed)
		force_sigsegv(ksig->sig, current);
	else
		signal_delivered(ksig, stepping);
}

/*
 * Nuke all other threads in the group.
 */
int zap_other_threads(struct task_struct *p)
{
	struct task_struct *t = p;
	int count = 0;

	p->signal->group_stop_count = 0;
	
	//task_lock(p);
	while_each_thread(p, t) {
		task_clear_jobctl_pending(t, JOBCTL_PENDING_MASK);
		count++;

		/* Don't bother with already dead threads */
		if (t->exit_state)
			continue;
		sigaddset(&t->pending.signal, SIGKILL);
		signal_wake_up(t, 1);
	}
	//task_unlock(p);

	return count;
}

int copy_siginfo_to_user(siginfo_t __user *to, const siginfo_t *from)
{
	int err;

	if (!access_ok (VERIFY_WRITE, to, sizeof(siginfo_t)))
		return -EFAULT;
	if (from->si_code < 0)
		return __copy_to_user(to, from, sizeof(siginfo_t))
			? -EFAULT : 0;
	/*
	 * If you change siginfo_t structure, please be sure
	 * this code is fixed accordingly.
	 * Please remember to update the signalfd_copyinfo() function
	 * inside fs/signalfd.c too, in case siginfo_t changes.
	 * It should never copy any pad contained in the structure
	 * to avoid security leaks, but must copy the generic
	 * 3 ints plus the relevant union member.
	 */
	err = __put_user(from->si_signo, &to->si_signo);
	err |= __put_user(from->si_errno, &to->si_errno);
	err |= __put_user((short)from->si_code, &to->si_code);
	switch (from->si_code & __SI_MASK) {
	case __SI_KILL:
		err |= __put_user(from->si_pid, &to->si_pid);
		err |= __put_user(from->si_uid, &to->si_uid);
		break;
	case __SI_TIMER:
		 err |= __put_user(from->si_tid, &to->si_tid);
		 err |= __put_user(from->si_overrun, &to->si_overrun);
		 err |= __put_user(from->si_ptr, &to->si_ptr);
		break;
	case __SI_POLL:
		err |= __put_user(from->si_band, &to->si_band);
		err |= __put_user(from->si_fd, &to->si_fd);
		break;
	case __SI_FAULT:
		err |= __put_user(from->si_addr, &to->si_addr);
#ifdef __ARCH_SI_TRAPNO
		err |= __put_user(from->si_trapno, &to->si_trapno);
#endif
#ifdef BUS_MCEERR_AO
		/*
		 * Other callers might not initialize the si_lsb field,
		 * so check explicitly for the right codes here.
		 */
		if (from->si_signo == SIGBUS &&
		    (from->si_code == BUS_MCEERR_AR || from->si_code == BUS_MCEERR_AO))
			err |= __put_user(from->si_addr_lsb, &to->si_addr_lsb);
#endif
#ifdef SEGV_BNDERR
		if (from->si_signo == SIGSEGV && from->si_code == SEGV_BNDERR) {
			err |= __put_user(from->si_lower, &to->si_lower);
			err |= __put_user(from->si_upper, &to->si_upper);
		}
#endif
#ifdef SEGV_PKUERR
		if (from->si_signo == SIGSEGV && from->si_code == SEGV_PKUERR)
			err |= __put_user(from->si_pkey, &to->si_pkey);
#endif
		break;
	case __SI_CHLD:
		err |= __put_user(from->si_pid, &to->si_pid);
		err |= __put_user(from->si_uid, &to->si_uid);
		err |= __put_user(from->si_status, &to->si_status);
		err |= __put_user(from->si_utime, &to->si_utime);
		err |= __put_user(from->si_stime, &to->si_stime);
		break;
	case __SI_RT: /* This is not generated by the kernel as of now. */
	case __SI_MESGQ: /* But this is */
		err |= __put_user(from->si_pid, &to->si_pid);
		err |= __put_user(from->si_uid, &to->si_uid);
		err |= __put_user(from->si_ptr, &to->si_ptr);
		break;
#ifdef __ARCH_SIGSYS
	case __SI_SYS:
		err |= __put_user(from->si_call_addr, &to->si_call_addr);
		err |= __put_user(from->si_syscall, &to->si_syscall);
		err |= __put_user(from->si_arch, &to->si_arch);
		break;
#endif
	default: /* this is just in case for now ... */
		err |= __put_user(from->si_pid, &to->si_pid);
		err |= __put_user(from->si_uid, &to->si_uid);
		break;
	}
	return err;
}

/* System-call Part */

/**
 *  sys_restart_syscall - restart a system call
 */
SYSCALL_DEFINE0(restart_syscall)
{
	debug_syscall_print();
	return -EFAULT;
}


/*
 * This is also useful for kernel threads that want to temporarily
 * (or permanently) block certain signals.
 *
 * NOTE! Unlike the user-mode sys_sigprocmask(), the kernel
 * interface happily blocks "unblockable" signals like SIGKILL
 * and friends.
 */
int sigprocmask(int how, sigset_t *set, sigset_t *oldset)
{
	struct task_struct *tsk = current;
	sigset_t newset;

	/* Lockless, only current can change ->blocked, never from irq */
	if (oldset)
		*oldset = tsk->blocked;

	switch (how) {
	case SIG_BLOCK:
		sigorsets(&newset, &tsk->blocked, set);
		break;
	case SIG_UNBLOCK:
		sigandnsets(&newset, &tsk->blocked, set);
		break;
	case SIG_SETMASK:
		newset = *set;
		break;
	default:
		return -EINVAL;
	}

	printk("new ready set %lu\n", newset.sig[0]);
	__set_current_blocked(&newset);
	return 0;
}

/**
 *  sys_rt_sigprocmask - change the list of currently blocked signals
 *  @how: whether to add, remove, or set signals
 *  @nset: stores pending signals
 *  @oset: previous value of signal mask if non-null
 *  @sigsetsize: size of sigset_t type
 */
SYSCALL_DEFINE4(rt_sigprocmask, int, how, sigset_t __user *, nset,
		sigset_t __user *, oset, size_t, sigsetsize)
{
	sigset_t old_set, new_set;
	int error;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	old_set = current->blocked;

	if (nset) {
		if (copy_from_user(&new_set, nset, sizeof(sigset_t)))
			return -EFAULT;
		sigdelsetmask(&new_set, sigmask(SIGKILL)|sigmask(SIGSTOP));

	printk("new set %lu\n", new_set.sig[0]);
		error = sigprocmask(how, &new_set, NULL);
		if (error)
			return error;
	}

	if (oset) {
		if (copy_to_user(oset, &old_set, sizeof(sigset_t)))
			return -EFAULT;
	}
	printk("current blocked %lu\n", current->blocked.sig[0]);

	return 0;
}

static int do_sigpending(void *set, unsigned long sigsetsize)
{
	if (sigsetsize > sizeof(sigset_t))
		return -EINVAL;

	spin_lock_irq(&current->sighand->siglock);
	sigorsets(set, &current->pending.signal,
		  &current->signal->shared_pending.signal);
	spin_unlock_irq(&current->sighand->siglock);

	/* Outside the lock because only this thread touches it.  */
	sigandsets(set, &current->blocked, set);
	return 0;
}

/**
 *  sys_rt_sigpending - examine a pending signal that has been raised
 *			while blocked
 *  @uset: stores pending signals
 *  @sigsetsize: size of sigset_t type or larger
 */
SYSCALL_DEFINE2(rt_sigpending, sigset_t __user *, uset, size_t, sigsetsize)
{
	sigset_t set;
	int err = do_sigpending(&set, sigsetsize);
	if (!err && copy_to_user(uset, &set, sigsetsize))
		err = -EFAULT;
	return err;
}

struct sighand_struct *__lock_task_sighand(struct task_struct *tsk,
					   unsigned long *flags)
{
	struct sighand_struct *sighand;

	for (;;) {
		/*
		 * Disable interrupts early to avoid deadlocks.
		 * See rcu_read_unlock() comment header for details.
		 */
		local_irq_save(*flags);
		task_lock(tsk);
		sighand = tsk->sighand;
		if (unlikely(sighand == NULL)) {
			task_unlock(tsk);
			local_irq_restore(*flags);
			break;
		}
		/*
		 * This sighand can be already freed and even reused, but
		 * we rely on SLAB_TYPESAFE_BY_RCU and sighand_ctor() which
		 * initializes ->siglock: this slab can't go away, it has
		 * the same object type, ->siglock can't be reinitialized.
		 *
		 * We need to ensure that tsk->sighand is still the same
		 * after we take the lock, we can race with de_thread() or
		 * __exit_signal(). In the latter case the next iteration
		 * must see ->sighand == NULL.
		 */
		spin_lock(&sighand->siglock);
		if (likely(sighand == tsk->sighand)) {
			task_unlock(tsk);
			break;
		}
		spin_unlock(&sighand->siglock);
		task_unlock(tsk);
		local_irq_restore(*flags);
	}

	return sighand;
}


int do_send_sig_info(int sig, struct siginfo *info, struct task_struct *p,
			bool group)
{
	unsigned long flags;
	int ret = -ESRCH;

	printk("DEBUGGING, entering kill\n");
	if (lock_task_sighand(p, &flags)) {
		ret = send_signal(sig, info, p, group);
		unlock_task_sighand(p, &flags);
	}

	return ret;
}

int kill_pid_info(int sig, struct siginfo *info, pid_t pid)
{
	int error = -ESRCH;
	struct task_struct *p;

	for (;;) {
		p = find_task_by_pid(pid);
		if (p)
			error = do_send_sig_info(sig, info, p, true);
		if (likely(!p || error != -ESRCH))
			return error;

		/*
		 * The task was unhashed in between, try again.  If it
		 * is dead, pid_task() will return NULL, if we race with
		 * de_thread() it will find the new leader.
		 */
	}
}

/*
 * kill_something_info() interprets pid in interesting ways just like kill(2).
 *
 * POSIX specifies that kill(-1,sig) is unspecified, but what we have
 * is probably wrong.  Should make it like BSD or SYSV.
 */

static int kill_something_info(int sig, struct siginfo *info, pid_t pid)
{
	int ret;

	if (pid > 0) {
		ret = kill_pid_info(sig, info, pid);
		return ret;
	}
	BUG_ON(pid < 0);

	return ret;
}


/**
 *  sys_kill - send a signal to a process
 *  @pid: the PID of the process
 *  @sig: signal to be sent
 */
SYSCALL_DEFINE2(kill, pid_t, pid, int, sig)
{
	struct siginfo info;

	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code = SI_USER;
	info.si_pid = current->group_leader->pid;
	info.si_uid = 0;
	return kill_something_info(sig, &info, pid);
}

static void __user *sig_handler(struct task_struct *t, int sig)
{
	return t->sighand->action[sig - 1].sa.sa_handler;
}

static int sig_handler_ignored(void __user *handler, int sig)
{
	/* Is it explicitly or implicitly ignored? */
	return handler == SIG_IGN ||
		(handler == SIG_DFL && sig_kernel_ignore(sig));
}

/*
 * Remove signals in mask from the pending set and queue.
 * Returns 1 if any signals were found.
 *
 * All callers must be holding the siglock.
 */
static int flush_sigqueue_mask(sigset_t *mask, struct sigpending *s)
{
	struct sigqueue *q, *n;
	sigset_t m;

	sigandsets(&m, mask, &s->signal);
	if (sigisemptyset(&m))
		return 0;

	sigandnsets(&s->signal, &s->signal, mask);
	list_for_each_entry_safe(q, n, &s->list, list) {
		if (sigismember(mask, q->info.si_signo)) {
			list_del_init(&q->list);
			__sigqueue_free(q);
		}
	}
	return 1;
}

int do_sigaction(int sig, struct k_sigaction *act, struct k_sigaction *oact)
{
	struct task_struct *p = current, *t;
	struct k_sigaction *k;
	sigset_t mask;

	if (!valid_signal(sig) || sig < 1 || (act && sig_kernel_only(sig)))
		return -EINVAL;

	k = &p->sighand->action[sig-1];

	spin_lock_irq(&p->sighand->siglock);
	if (oact)
		*oact = *k;

	if (act) {
		sigdelsetmask(&act->sa.sa_mask,
			      sigmask(SIGKILL) | sigmask(SIGSTOP));
		*k = *act;
		/*
		 * POSIX 3.3.1.3:
		 *  "Setting a signal action to SIG_IGN for a signal that is
		 *   pending shall cause the pending signal to be discarded,
		 *   whether or not it is blocked."
		 *
		 *  "Setting a signal action to SIG_DFL for a signal that is
		 *   pending and whose default action is to ignore the signal
		 *   (for example, SIGCHLD), shall cause the pending signal to
		 *   be discarded, whether or not it is blocked"
		 */
		if (sig_handler_ignored(sig_handler(p, sig), sig)) {
			sigemptyset(&mask);
			sigaddset(&mask, sig);
			flush_sigqueue_mask(&mask, &p->signal->shared_pending);
			//spin_lock(&p->signal->stats_lock);
			for_each_thread(p, t)
				flush_sigqueue_mask(&mask, &t->pending);
			//spin_unlock(&p->signal->stats_lock);
		}
	}

	spin_unlock_irq(&p->sighand->siglock);
	return 0;
}

/**
 *  sys_rt_sigaction - alter an action taken by a process
 *  @sig: signal to be sent
 *  @act: new sigaction
 *  @oact: used to save the previous sigaction
 *  @sigsetsize: size of sigset_t type
 */
SYSCALL_DEFINE4(rt_sigaction, int, sig,
		const struct sigaction __user *, act,
		struct sigaction __user *, oact,
		size_t, sigsetsize)
{
	struct k_sigaction new_sa, old_sa;
	int ret = -EINVAL;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		goto out;

	if (act) {
		if (copy_from_user(&new_sa.sa, act, sizeof(new_sa.sa)))
			return -EFAULT;
	}

	ret = do_sigaction(sig, act ? &new_sa : NULL, oact ? &old_sa : NULL);

	if (!ret && oact) {
		if (copy_to_user(oact, &old_sa.sa, sizeof(old_sa.sa)))
			return -EFAULT;
	}
out:
	return ret;
}

static int do_rt_sigqueueinfo(pid_t pid, int sig, siginfo_t *info)
{
	/* Not even root can pretend to send signals from the kernel.
	 * Nor can they impersonate a kill()/tgkill(), which adds source info.
	 */
	if ((info->si_code >= 0 || info->si_code == SI_TKILL) &&
	    (current->pid != pid))
		return -EPERM;

	info->si_signo = sig;

	/* POSIX.1b doesn't mention process groups.  */
	return kill_pid_info(sig, info, pid);
}

/**
 *  sys_rt_sigqueueinfo - send signal information to a signal
 *  @pid: the PID of the thread
 *  @sig: signal to be sent
 *  @uinfo: signal info to be sent
 */
SYSCALL_DEFINE3(rt_sigqueueinfo, pid_t, pid, int, sig,
		siginfo_t __user *, uinfo)
{
	siginfo_t info;
	if (copy_from_user(&info, uinfo, sizeof(siginfo_t)))
		return -EFAULT;
	return do_rt_sigqueueinfo(pid, sig, &info);
}

static int sigsuspend(sigset_t *set)
{
	current->saved_sigmask = current->blocked;
	set_current_blocked(set);

	while (!signal_pending(current)) {
		__set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	set_restore_sigmask();
	return -ERESTARTNOHAND;
}

/**
 *  sys_rt_sigsuspend - replace the signal mask for a value with the
 *	@unewset value until a signal is received
 *  @unewset: new signal mask value
 *  @sigsetsize: size of sigset_t type
 */
SYSCALL_DEFINE2(rt_sigsuspend, sigset_t __user *, unewset, size_t, sigsetsize)
{
	sigset_t newset;

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (copy_from_user(&newset, unewset, sizeof(newset)))
		return -EFAULT;
	return sigsuspend(&newset);
}
