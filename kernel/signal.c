/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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

#ifdef CONFIG_DEBUG_SIGNAL
#define debug_signal(fmt, ...)					\
	pr_debug("%s() CPU:%d " fmt "\n",			\
		__func__, smp_processor_id(), __VA_ARGS__)
#else
#define debug_signal(fmt, ...)	do { } while (0)
#endif

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

static void __sigqueue_free(struct sigqueue *q)
{
	kfree(q);
}

void flush_sigqueue(struct sigpending *queue)
{
	struct sigqueue *q;

	sigemptyset(&queue->signal);
	while (!list_empty(&queue->list)) {
		q = list_entry(queue->list.next, struct sigqueue , list);
		list_del_init(&q->list);
		__sigqueue_free(q);
	}
}

/*
 * Flush all pending signals for this kthread.
 */
void flush_signals(struct task_struct *t)
{
	unsigned long flags;

	spin_lock_irqsave(&t->sighand->siglock, flags);
	clear_tsk_thread_flag(t, TIF_SIGPENDING);
	flush_sigqueue(&t->pending);
	flush_sigqueue(&t->signal->shared_pending);
	spin_unlock_irqrestore(&t->sighand->siglock, flags);
}

void ignore_signals(struct task_struct *t)
{
	int i;

	for (i = 0; i < _NSIG; ++i)
		t->sighand->action[i].sa.sa_handler = SIG_IGN;

	flush_signals(t);
}

/* Flush all handlers for a task. */
void flush_signal_handlers(struct task_struct *t, int force_default)
{
	int i;
	struct k_sigaction *ka = &t->sighand->action[0];
	for (i = _NSIG ; i != 0 ; i--) {
		if (force_default || ka->sa.sa_handler != SIG_IGN)
			ka->sa.sa_handler = SIG_DFL;
		ka->sa.sa_flags = 0;
#ifdef __ARCH_HAS_SA_RESTORER
		ka->sa.sa_restorer = NULL;
#endif
		sigemptyset(&ka->sa.sa_mask);
		ka++;
	}
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
	if (!print_fatal_signals)
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
void signal_wake_up(struct task_struct *t, bool resume)
{
	unsigned int state;

	state = resume ? TASK_WAKEKILL : 0;

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

static inline int legacy_queue(struct sigpending *signals, int sig)
{
	return (sig < SIGRTMIN) && sigismember(&signals->signal, sig);
}

static inline int is_si_special(const struct siginfo *info)
{
	return info <= SEND_SIG_FORCED;
}

static inline bool si_fromuser(const struct siginfo *info)
{
	return info == SEND_SIG_NOINFO ||
		(!is_si_special(info) && SI_FROMUSER(info));
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

	/* Just override now, otherwise we need to check rlimit here */
	if (override_rlimit || true)
		q = kmalloc(sizeof(*q), flags | GFP_KERNEL);
	else
		print_dropped_signal(sig);

	if (likely(q)) {
		INIT_LIST_HEAD(&q->list);
		q->flags = 0;
	}
	return q;
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

			spin_lock(&tasklist_lock);
			do {
				task_clear_jobctl_pending(t, JOBCTL_PENDING_MASK);
				sigaddset(&t->pending.signal, SIGKILL);
				signal_wake_up(t, 1);
			} while_each_thread(p, t);
			spin_unlock(&tasklist_lock);
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

/**
 * send_signal
 * @sig: the signal to deliver
 * @info: information of how signal is generated
 * @t: the target task to kill
 * @group: true to kill whole thread group, false to kill @t only
 *
 * Must enter with @sighand->siglock held!
 */
static int
send_signal(int sig, struct siginfo *info, struct task_struct *t, int group)
{
	struct sigpending *pending;
	struct sigqueue *q;
	int override_rlimit;
	int ret = 0;

	BUG_ON(!spin_is_locked(&t->sighand->siglock));

	pending = group ? &t->signal->shared_pending : &t->pending;

	/*
	 * Legacy signals can not be queued if it is already pending.
	 * POSIX has defined real-time extensions to signals,
	 * and the signal that being generated more than once
	 * can be queued, and handled one by one, no one is missed.
	 */
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

	/*
	 * Allocate a sigqueue, copy info into that
	 * and insert it into sigpending:
	 */
	q = __sigqueue_alloc(sig, t, GFP_ATOMIC, override_rlimit);
	if (likely(q)) {
		list_add_tail(&q->list, &pending->list);
		switch ((unsigned long) info) {
		case (unsigned long) SEND_SIG_NOINFO:
			q->info.si_signo = sig;
			q->info.si_errno = 0;
			q->info.si_code = SI_USER;
			q->info.si_pid = current->tgid;
			q->info.si_uid = current_uid();
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
	spin_lock(&tasklist_lock);
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
	spin_unlock(&tasklist_lock);
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

void __set_current_blocked(const sigset_t *newset)
{
	struct task_struct *tsk = current;

	spin_lock_irq(&tsk->sighand->siglock);
	__set_task_blocked(tsk, newset);
	spin_unlock_irq(&tsk->sighand->siglock);
}

static inline void task_cputime(struct task_struct *t,
				cputime_t *utime, cputime_t *stime)
{
	if (utime)
		*utime = t->utime;
	if (stime)
		*stime = t->stime;
}

/*
 * Let a parent know about the death of a child.
 * For a stopped/continued status change, use do_notify_parent_cldstop instead.
 *
 * Returns true if our parent ignored us and so we've switched to
 * self-reaping.
 */
bool do_notify_parent(struct task_struct *tsk, int sig)
{
	struct siginfo info;
	unsigned long flags;
	struct sighand_struct *psig;
	bool autoreap = false;

	BUG_ON(sig == -1);

 	/* do_notify_parent_cldstop should have been called instead.  */
 	BUG_ON(task_is_stopped_or_traced(tsk));

	BUG_ON(!tsk->ptrace &&
	       (tsk->group_leader != tsk || !thread_group_empty(tsk)));

	if (sig != SIGCHLD) {
		/*
		 * This is only possible if parent == real_parent.
		 * Check if it has changed security domain.
		 */
		if (tsk->parent_exec_id != tsk->parent->self_exec_id)
			sig = SIGCHLD;
	}

	info.si_signo = sig;
	info.si_errno = 0;
	/*
	 * We are under tasklist_lock here so our parent is tied to
	 * us and cannot change.
	 *
	 * task_active_pid_ns will always return the same pid namespace
	 * until a task passes through release_task.
	 *
	 * write_lock() currently calls preempt_disable() which is the
	 * same as rcu_read_lock(), but according to Oleg, this is not
	 * correct to rely on this
	 */
	info.si_pid = tsk->pid;
	info.si_uid = 0;

#if 0
	task_cputime(tsk, &utime, &stime);
	info.si_utime = cputime_to_clock_t(utime + tsk->signal->utime);
	info.si_stime = cputime_to_clock_t(stime + tsk->signal->stime);
#endif

	info.si_status = tsk->exit_code & 0x7f;
	if (tsk->exit_code & 0x80)
		info.si_code = CLD_DUMPED;
	else if (tsk->exit_code & 0x7f)
		info.si_code = CLD_KILLED;
	else {
		info.si_code = CLD_EXITED;
		info.si_status = tsk->exit_code >> 8;
	}

	psig = tsk->parent->sighand;
	spin_lock_irqsave(&psig->siglock, flags);
	if (!tsk->ptrace && sig == SIGCHLD &&
	    (psig->action[SIGCHLD-1].sa.sa_handler == SIG_IGN ||
	     (psig->action[SIGCHLD-1].sa.sa_flags & SA_NOCLDWAIT))) {
		/*
		 * We are exiting and our parent doesn't care.  POSIX.1
		 * defines special semantics for setting SIGCHLD to SIG_IGN
		 * or setting the SA_NOCLDWAIT flag: we should be reaped
		 * automatically and not left for our parent's wait4 call.
		 * Rather than having the parent do it as a magic kind of
		 * signal handler, we just set this to tell do_exit that we
		 * can be cleaned up without becoming a zombie.  Note that
		 * we still call __wake_up_parent in this case, because a
		 * blocked sys_wait4 might now return -ECHILD.
		 *
		 * Whether we send SIGCHLD or not for SA_NOCLDWAIT
		 * is implementation-defined: we do (if you don't want
		 * it, just use SIG_IGN instead).
		 */
		autoreap = true;
		if (psig->action[SIGCHLD-1].sa.sa_handler == SIG_IGN)
			sig = 0;
	}

	if (valid_signal(sig) && sig)
		__group_send_sig_info(sig, &info, tsk->parent);

	__wake_up_parent(tsk, tsk->parent);

	spin_unlock_irqrestore(&psig->siglock, flags);

	return autoreap;
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

		sig->group_stop_count = 0;

		if (task_set_jobctl_pending(current, signr | gstop))
			sig->group_stop_count++;

		t = current;
		spin_lock(&tasklist_lock);
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
		spin_unlock(&tasklist_lock);
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

		/* Now we don't run again until woken by SIGCONT or SIGKILL */
		schedule();
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
	list_for_each_entry(q, &list->list, list) {
		if (q->info.si_signo == sig) {
			if (first)
				goto still_pending;
			first = q;
		}
	}

	sigdelset(&list->signal, sig);

	if (first) {
still_pending:
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
}

static int __dequeue_signal(struct sigpending *pending, sigset_t *mask,
			siginfo_t *info)
{
	int sig = next_signal(pending, mask);

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

		 /* 
		  * Don't warn me now, now I implemented itimer on
		  * low resoulation timer (old way), which requires
		  * sending SIGALRM periodically
		  *  - yilun
		  */
#if 0
		if (unlikely(signr == SIGALRM)) {
			WARN_ON(1);
		}
#endif
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
		WARN_ON(1);
		do_schedule_next_timer(info);
		spin_lock(&tsk->sighand->siglock);
	}
	return signr;
}

/*
 * Return 1 if we have a user-registed signal handler
 * to handle; Otherwise the signal is SIG_DFL or SIG_IGN,
 * or there is no signals.
 */
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

		debug_signal("dequeue_signr: %d, handler:%p", signr,
			signr > 0 ? (&sighand->action[signr-1])->sa.sa_handler : NULL);

		/*
		 * No signal to handle
		 * Wil return 0
		 */
		if (!signr)
			break;

		ka = &sighand->action[signr-1];

		/*
		 * Signal catched, but ignore it:
		 */
		if (ka->sa.sa_handler == SIG_IGN)
			continue;

		/*
		 * Signal catched with customized signal handler.
		 * Then return and let arch code run the handler:
		 */
		if (ka->sa.sa_handler != SIG_DFL) {
			ksig->ka = *ka;

			if (ka->sa.sa_flags & SA_ONESHOT)
				ka->sa.sa_handler = SIG_DFL;

			break; /* will return non-zero "signr" value */
		}

		/*
		 * Signal catched with default action:
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

		/*
		 * Death signals, no core dump.
		 */
		do_group_exit(ksig->info.si_signo);
		/* NOTREACHED */
	}
	spin_unlock_irq(&sighand->siglock);

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
 * Called during do_group_exit()
 */
int zap_other_threads(struct task_struct *p)
{
	struct task_struct *t = p;
	int count = 0;

	p->signal->group_stop_count = 0;

	spin_lock(&tasklist_lock);
	while_each_thread(p, t) {
		task_clear_jobctl_pending(t, JOBCTL_PENDING_MASK);
		count++;

		/* Don't bother with already dead threads */
		if (t->exit_state)
			continue;
		sigaddset(&t->pending.signal, SIGKILL);
		signal_wake_up(t, 1);
	}
	spin_unlock(&tasklist_lock);

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

void exit_signals(struct task_struct *tsk)
{
	int group_stop = 0;
	sigset_t unblocked;

	if (thread_group_empty(tsk) || signal_group_exit(tsk->signal)) {
		tsk->flags |= PF_EXITING;
		return;
	}

	spin_lock_irq(&tsk->sighand->siglock);
	/*
	 * From now this task is not visible for group-wide signals,
	 * see wants_signal(), do_signal_stop().
	 */
	tsk->flags |= PF_EXITING;

	if (!signal_pending(tsk))
		goto out;

	unblocked = tsk->blocked;
	signotset(&unblocked);
	retarget_shared_pending(tsk, &unblocked);

	if (unlikely(tsk->jobctl & JOBCTL_STOP_PENDING) &&
	    task_participate_group_stop(tsk))
		group_stop = CLD_STOPPED;
out:
	spin_unlock_irq(&tsk->sighand->siglock);

	/*
	 * If group stop has completed, deliver the notification.  This
	 * should always go to the real parent of the group leader.
	 */
	if (unlikely(group_stop)) {
		spin_lock(&tasklist_lock);
		do_notify_parent_cldstop(tsk, false, group_stop);
		spin_unlock(&tasklist_lock);
	}
}

static void __flush_itimer_signals(struct sigpending *pending)
{
	sigset_t signal, retain;
	struct sigqueue *q, *n;

	signal = pending->signal;
	sigemptyset(&retain);

	list_for_each_entry_safe(q, n, &pending->list, list) {
		int sig = q->info.si_signo;

		if (likely(q->info.si_code != SI_TIMER)) {
			sigaddset(&retain, sig);
		} else {
			sigdelset(&signal, sig);
			list_del_init(&q->list);
			__sigqueue_free(q);
		}
	}

	sigorsets(&pending->signal, &signal, &retain);
}

void flush_itimer_signals(void)
{
	struct task_struct *tsk = current;
	unsigned long flags;

	spin_lock_irqsave(&tsk->sighand->siglock, flags);
	__flush_itimer_signals(&tsk->pending);
	__flush_itimer_signals(&tsk->signal->shared_pending);
	spin_unlock_irqrestore(&tsk->sighand->siglock, flags);
}

/* System-call Part */

/**
 *  sys_restart_syscall - restart a system call
 */
SYSCALL_DEFINE0(restart_syscall)
{
	struct restart_block *restart = &current->restart_block;
	return restart->fn(restart);
}

long do_no_restart_syscall(struct restart_block *param)
{
	return -EINTR;
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

	old_set = current->blocked;

	if (nset) {
		if (copy_from_user(&new_set, nset, sizeof(sigset_t))) {
			error = -EFAULT;
			goto out;
		}
		sigdelsetmask(&new_set, sigmask(SIGKILL)|sigmask(SIGSTOP));

		error = sigprocmask(how, &new_set, NULL);
		if (error)
			goto out;
	}

	syscall_enter("how: %d, nset: %#lx,oset: %#lx\n",
		how, new_set.sig[0], old_set.sig[0]);

	if (oset) {
		if (copy_to_user(oset, &old_set, sizeof(sigset_t))) {
			error = -EFAULT;
			goto out;
		}
	}

out:
	syscall_exit(error);
	return error;
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
	int err;

	syscall_enter("uset: %p, sigsetsize: %zu\n",
		uset, sigsetsize);

	err = do_sigpending(&set, sigsetsize);
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

/*
 * A wrapper for send_signal()
 * Acquire the sighand->siglock first:
 */
int do_send_sig_info(int sig, struct siginfo *info,
		     struct task_struct *p, bool group)
{
	unsigned long flags;
	int ret = -ESRCH;

	if (lock_task_sighand(p, &flags)) {
		ret = send_signal(sig, info, p, group);
		unlock_task_sighand(p, &flags);
	}

	return ret;
}

static int check_kill_permission(int sig, struct siginfo *info,
				 struct task_struct *t)
{
	if (!valid_signal(sig))
		return -EINVAL;

	/* kernel can send do anything */
	if (!si_fromuser(info))
		return 0;

	if (!same_thread_group(current, t))
		return -EPERM;

	return 0;
}

/*
 * send signal info to all the members of a group
 */
int group_send_sig_info(int sig, struct siginfo *info, struct task_struct *p)
{
	int ret;

	ret = check_kill_permission(sig, info, p);
	if (!ret && sig)
		ret = do_send_sig_info(sig, info, p, true);

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
		 * is dead, find_task() will return NULL, if we race with
		 * de_thread() it will find the new leader.
		 */
	}
}

/*
 * __kill_pgrp_info() sends a signal to a process group: this is what the tty
 * control characters do (^C, ^Z etc)
 * - the caller must hold at least a readlock on tasklist_lock
 */
int __kill_pgrp_info(int sig, struct siginfo *info, pid_t pgrp)
{
	/* TODO */
	WARN_ON_ONCE(1);
	return 0;
}

/*
 * kill_something_info() interprets pid in interesting ways just like kill(2).
 *
 * POSIX specifies that kill(-1,sig) is unspecified, but what we have
 * is probably wrong.  Should make it like BSD or SYSV.
 *
 * Lego also make kill(-1,sig) invalid.
 */
static int kill_something_info(int sig, struct siginfo *info, pid_t pid)
{
	if (pid > 0)
		return kill_pid_info(sig, info, pid);
	WARN_ON(pid < 0);
	return -EPERM;
}

/**
 *  sys_kill - send a signal to a process
 *  @pid: the PID of the process
 *  @sig: signal to be sent
 */
SYSCALL_DEFINE2(kill, pid_t, pid, int, sig)
{
	struct siginfo info;

	syscall_enter("pid: %u, sig: %d\n", pid, sig);

	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code = SI_USER;
	info.si_pid = current->tgid;
	info.si_uid = 0;

	return kill_something_info(sig, &info, pid);
}

static int
do_send_specific(pid_t tgid, pid_t pid, int sig, struct siginfo *info)
{
	struct task_struct *p;
	int error = -ESRCH;

	p = find_task_by_pid(pid);
	if (p && (tgid <= 0 || p->tgid == tgid)) {
		error = check_kill_permission(sig, info, p);
		/*
		 * The null signal is a permissions and process existence
		 * probe.  No signal is actually delivered.
		 */
		if (!error && sig) {
			error = do_send_sig_info(sig, info, p, false);
			/*
			 * If lock_task_sighand() failed we pretend the task
			 * dies after receiving the signal. The window is tiny,
			 * and the signal is private anyway.
			 */
			if (unlikely(error == -ESRCH))
				error = 0;
		}
	}

	return error;
}

static int do_tkill(pid_t tgid, pid_t pid, int sig)
{
	struct siginfo info = {};

	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code = SI_TKILL;
	info.si_pid = current->tgid;
	info.si_uid = current_uid();

	return do_send_specific(tgid, pid, sig, &info);
}

/**
 *  sys_tgkill - send signal to one specific thread
 *  @tgid: the thread group ID of the thread
 *  @pid: the PID of the thread
 *  @sig: signal to be sent
 *
 *  This syscall also checks the @tgid and returns -ESRCH even if the PID
 *  exists but it's not belonging to the target process anymore. This
 *  method solves the problem of threads exiting and PIDs getting reused.
 */
SYSCALL_DEFINE3(tgkill, pid_t, tgid, pid_t, pid, int, sig)
{
	syscall_enter("tgid:%u,pid:%u,sig:%d\n", tgid, pid, sig);

	/* This is only valid for single tasks */
	if (pid <= 0 || tgid <= 0)
		return -EINVAL;

	return do_tkill(tgid, pid, sig);
}

/**
 *  sys_tkill - send signal to one specific task
 *  @pid: the PID of the task
 *  @sig: signal to be sent
 *
 *  Send a signal to only one task, even if it's a CLONE_THREAD task.
 */
SYSCALL_DEFINE2(tkill, pid_t, pid, int, sig)
{
	syscall_enter("pid:%u,sig:%d\n", pid, sig);

	/* This is only valid for single tasks */
	if (pid <= 0)
		return -EINVAL;

	return do_tkill(0, pid, sig);
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

			spin_lock(&tasklist_lock);
			for_each_thread(p, t)
				flush_sigqueue_mask(&mask, &t->pending);
			spin_unlock(&tasklist_lock);
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

	if (act) {
		if (copy_from_user(&new_sa.sa, act, sizeof(new_sa.sa))) {
			ret = -EFAULT;
			goto out;
		}
	}

	syscall_enter("sig:%d,n_handler:%p,n_flags:%#lx,n_restore:%p,n_mast:%lx\n",
		sig, new_sa.sa.sa_handler, new_sa.sa.sa_flags, new_sa.sa.sa_restorer,
		new_sa.sa.sa_mask.sig[0]);

	ret = do_sigaction(sig, act ? &new_sa : NULL, oact ? &old_sa : NULL);
	if (!ret && oact) {
		if (copy_to_user(oact, &old_sa.sa, sizeof(old_sa.sa)))
			ret = -EFAULT;
	}

out:
	syscall_exit(ret);
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

	syscall_enter("pid:%u,sig:%d,uinfo:%p\n", pid, sig, uinfo);

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

	syscall_enter("unewset: %p, sigsetsize: %zu\n",
		unewset, sigsetsize);

	/* XXX: Don't preclude handling different sized sigset_t's.  */
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if (copy_from_user(&newset, unewset, sizeof(newset)))
		return -EFAULT;
	return sigsuspend(&newset);
}

static int
do_sigaltstack (const stack_t __user *uss, stack_t __user *uoss, unsigned long sp)
{
	stack_t oss;
	int error;

	oss.ss_sp = (void __user *) current->sas_ss_sp;
	oss.ss_size = current->sas_ss_size;
	oss.ss_flags = sas_ss_flags(sp) |
		(current->sas_ss_flags & SS_FLAG_BITS);

	if (uss) {
		void __user *ss_sp;
		size_t ss_size;
		unsigned ss_flags;
		int ss_mode;

		error = -EFAULT;
		if (!access_ok(VERIFY_READ, uss, sizeof(*uss)))
			goto out;
		error = __get_user(ss_sp, &uss->ss_sp) |
			__get_user(ss_flags, &uss->ss_flags) |
			__get_user(ss_size, &uss->ss_size);
		if (error)
			goto out;

		error = -EPERM;
		if (on_sig_stack(sp))
			goto out;

		ss_mode = ss_flags & ~SS_FLAG_BITS;
		error = -EINVAL;
		if (ss_mode != SS_DISABLE && ss_mode != SS_ONSTACK &&
				ss_mode != 0)
			goto out;

		if (ss_mode == SS_DISABLE) {
			ss_size = 0;
			ss_sp = NULL;
		} else {
			error = -ENOMEM;
			if (ss_size < MINSIGSTKSZ)
				goto out;
		}

		current->sas_ss_sp = (unsigned long) ss_sp;
		current->sas_ss_size = ss_size;
		current->sas_ss_flags = ss_flags;
	}

	error = 0;
	if (uoss) {
		error = -EFAULT;
		if (!access_ok(VERIFY_WRITE, uoss, sizeof(*uoss)))
			goto out;
		error = __put_user(oss.ss_sp, &uoss->ss_sp) |
			__put_user(oss.ss_size, &uoss->ss_size) |
			__put_user(oss.ss_flags, &uoss->ss_flags);
	}

out:
	return error;
}

SYSCALL_DEFINE2(sigaltstack, const stack_t __user *, uss, stack_t __user *, uoss)
{
	syscall_enter("uss: %p, uoss: %p\n", uss, uoss);
	return do_sigaltstack(uss, uoss, current_pt_regs()->sp);
}

int restore_altstack(const stack_t __user *uss)
{
	int err = do_sigaltstack(uss, NULL, current_pt_regs()->sp);
	/* squash all but EFAULT for now */
	return err == -EFAULT ? err : 0;
}

/**
 *  do_sigtimedwait - wait for queued signals specified in @which
 *  @which: queued signals to wait for
 *  @info: if non-null, the signal's siginfo is returned here
 *  @ts: upper bound on process time suspension
 */
int do_sigtimedwait(const sigset_t *which, siginfo_t *info,
		    const struct timespec *ts)
{
	ktime_t timeout = KTIME_MAX;
	struct task_struct *tsk = current;
	sigset_t mask = *which;
	int sig, ret = 0;

	if (ts) {
		if (!timespec_valid(ts))
			return -EINVAL;
		timeout = timespec_to_ktime(*ts);
	}

	/*
	 * Invert the set of allowed signals to get those we want to block.
	 */
	sigdelsetmask(&mask, sigmask(SIGKILL) | sigmask(SIGSTOP));
	signotset(&mask);

	spin_lock_irq(&tsk->sighand->siglock);
	sig = dequeue_signal(tsk, &mask, info);
	if (!sig && timeout) {
		/*
		 * None ready, temporarily unblock those we're interested
		 * while we are sleeping in so that we'll be awakened when
		 * they arrive. Unblocking is always fine, we can avoid
		 * set_current_blocked().
		 */
		tsk->real_blocked = tsk->blocked;
		sigandsets(&tsk->blocked, &tsk->blocked, &mask);
		recalc_sigpending();
		spin_unlock_irq(&tsk->sighand->siglock);

		__set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(timeout);

		spin_lock_irq(&tsk->sighand->siglock);
		__set_task_blocked(tsk, &tsk->real_blocked);
		sigemptyset(&tsk->real_blocked);
		sig = dequeue_signal(tsk, &mask, info);
	}
	spin_unlock_irq(&tsk->sighand->siglock);

	if (sig)
		return sig;
	return ret ? -EINTR : -EAGAIN;
}

/**
 *  sys_rt_sigtimedwait - synchronously wait for queued signals specified
 *			in @uthese
 *  @uthese: queued signals to wait for
 *  @uinfo: if non-null, the signal's siginfo is returned here
 *  @uts: upper bound on process time suspension
 *  @sigsetsize: size of sigset_t type
 */
SYSCALL_DEFINE4(rt_sigtimedwait, const sigset_t __user *, uthese,
		siginfo_t __user *, uinfo, const struct timespec __user *, uts,
		size_t, sigsetsize)
{
	sigset_t these;
	struct timespec ts;
	siginfo_t info;
	int ret;

	__syscall_enter();

	if (copy_from_user(&these, uthese, sizeof(these)))
		return -EFAULT;

	if (uts) {
		if (copy_from_user(&ts, uts, sizeof(ts)))
			return -EFAULT;
	}

	ret = do_sigtimedwait(&these, &info, uts ? &ts : NULL);

	if (ret > 0 && uinfo) {
		if (copy_siginfo_to_user(uinfo, &info))
			ret = -EFAULT;
	}

	return ret;
}

SYSCALL_DEFINE0(pause)
{
	__syscall_enter();
	while (!signal_pending(current)) {
		__set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	return -ERESTARTNOHAND;
}

void dump_sigaction(struct sigaction *action, const char *prefix)
{
	if (!action || !prefix)
		return;

	if (action->sa_handler == SIG_IGN)
		pr_debug("%ssa_handler: SIG_IGN\n", prefix);
	else if (action->sa_handler == SIG_DFL)
		pr_debug("%ssa_handler: SIG_DFL\n", prefix);
	else
		pr_debug("%ssa_handler: %p\n", prefix, action->sa_handler);

	pr_debug("%ssa_flags:   %#lx\n", prefix, action->sa_flags);
	pr_debug("%ssa_restore: %p\n", prefix, action->sa_restorer);
	pr_debug("%ssa_mask:    %#lx\n", prefix, action->sa_mask.sig[0]);
}
