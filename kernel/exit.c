/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/wait.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/syscalls.h>

static void exit_mm(struct task_struct *tsk)
{
	struct mm_struct *mm = tsk->mm;

	mm_release(tsk, mm);
	barrier();
	tsk->mm = NULL;
	mmput(mm);
}

void exit_files(struct task_struct *tsk)
{
	/* TODO */
}

void __noreturn do_exit(long code)
{
	struct task_struct *tsk = current;
	int group_dead;

	if (unlikely(!tsk->pid))
		panic("Attempted to kill the idle task!");

	if (unlikely(in_atomic())) {
		pr_info("note: %s[%d] exited with preempt_count %d\n",
			current->comm, current->pid, preempt_count());
		preempt_count_set(0);
	}

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

	group_dead = atomic_dec_and_test(&tsk->signal->live);

	tsk->exit_code = code;

	exit_mm(tsk);
	exit_files(tsk);
	exit_thread(tsk);

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

	pr_info("%s():pid:%u,tgid:%u\n", FUNC, current->pid, current->tgid);

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

static inline pid_t task_pgrp(struct task_struct *task)
{
	/*
	 * TODO:
	 * Of course this is not the process group id
	 * Assume there is only one process in a process group
	 * and use the pid of group leader as process group id
	 */
	return task->group_leader->pid;
}

/*
 * Determine if a process group is "orphaned", according to the POSIX
 * definition in 2.2.2.52.  Orphaned process groups are not to be affected
 * by terminal-generated stop signals.  Newly orphaned process groups are
 * to receive a SIGHUP and a SIGCONT.
 *
 * "I ask you, have you ever known what it is to be an orphan?"
 */
static int will_become_orphaned_pgrp(pid_t pid, struct task_struct *ignored_task)
{
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

SYSCALL_DEFINE1(exit, int, error_code)
{
	syscall_enter();
	pr_info("%s(): error_code: %d\n", FUNC, error_code);
	do_exit((error_code&0xff)<<8);

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
	syscall_enter();
	pr_info("%s(): error_code: %d\n", FUNC, error_code);

	do_group_exit((error_code & 0xff) << 8);

	/* NOTREACHED */
	BUG();
	return 0;
}
