/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * execve()-related syscalls are processor-specific
 * Memory component does not this syscall, hence we move it to here.
 */

#include <lego/slab.h>
#include <lego/sched.h>
#include <lego/ptrace.h>
#include <lego/kernel.h>
#include <lego/spinlock.h>
#include <lego/syscalls.h>
#include <lego/uaccess.h>
#include <lego/fit_ibapi.h>

#include <processor/fs.h>
#include <processor/processor.h>
#include <processor/distvm.h>

static int exec_mmap(void)
{
	struct mm_struct *new_mm;
	struct mm_struct *old_mm;
	struct task_struct *tsk;

	new_mm = mm_alloc();
	if (!new_mm)
		return -ENOMEM;

	/* Notify parent that we're no longer interested in the old VM */
	tsk = current;
	old_mm = current->mm;
	mm_release(tsk, old_mm);

	/*
	 * We should do this before changing mm,
	 * because pcache_process_exit() needs old_mm to clean up
	 */
	mmput(old_mm);

	task_lock(tsk);
	tsk->mm = new_mm;
	tsk->active_mm = new_mm;
	activate_mm(old_mm, new_mm);
	task_unlock(tsk);

	return 0;
}

static __u32 count_param(const char __user * const * __user argv,
			 int max, __u32 *size)
{
	int i = 0;

	if (!argv || !size)
		return 0;

	for (;;) {
		const char *p;
		__u32 len;

		if (get_user(p, argv + i))
			return -EFAULT;

		if (!p)
			break;

		if (i >= max)
			return -E2BIG;

		/*
		 * Vulnerable to read-after-check attack?
		 */
		len = strnlen_user(p, MAX_ARG_STRLEN);
		if (unlikely(!len))
			return -EINVAL;

		*size += len;
		i++;
	}
	return i;
}

/* Copy strings from userspace to core-kernel paylaod */
static int copy_strings(__u32 argc, const char __user * const * __user argv,
			struct p2m_execve_struct *payload, __u32 *array_oft)
{
	int i;
	long copied;
	char *dst;
	const char *src;

	BUG_ON(!argc || !argv || !payload || !array_oft);

	dst = (char *)&(payload->array) + *array_oft;
	for (i = 0; i < argc; i++) {
		if (get_user(src, argv + i))
			return -EFAULT;

		copied = strncpy_from_user(dst, src, MAX_ARG_STRLEN);
		if (unlikely(copied < 0))
			return -EFAULT;

		copied++; /* including terminal NULL */
		*array_oft += copied;
		dst += copied;
	}

	return 0;
}

/*
 * Processor-Component
 * Prepare the payload being sent to memory-component
 */
static void *prepare_exec_payload(const char __user *filename,
				  const char __user * const * __user argv,
				  const char __user * const * __user envp,
				  __u32 *payload_size)
{
	__u32 argc, envc, size = 0, array_oft = 0;
	long copied;
	struct p2m_execve_struct *payload;

	/* Count the total payload size first */
	argc = count_param(argv, MAX_ARG_STRINGS, &size);
	if (argc < 0)
		return ERR_PTR(argc);

	envc = count_param(envp, MAX_ARG_STRINGS, &size);
	if (envc < 0)
		return ERR_PTR(envc);

	/* then allocate payload */
	*payload_size = sizeof(*payload) + size - sizeof(char *);
	payload = kzalloc(*payload_size, GFP_KERNEL);
	if (!payload)
		return ERR_PTR(-ENOMEM);

	/* then copy strings and fill payload */
	payload->pid = current->tgid;
	payload->payload_size = *payload_size;
	payload->argc = argc;
	payload->envc = envc;

	copied = strncpy_from_user(payload->filename, filename, MAX_FILENAME_LENGTH);
	if (unlikely(copied < 0))
		goto out;

	array_oft = 0;
	if (copy_strings(argc, argv, payload, &array_oft))
		goto out;

	if (copy_strings(envc, envp, payload, &array_oft))
		goto out;

	return payload;

out:
	kfree(payload);
	return ERR_PTR(-EFAULT);
}

static void *prepare_exec_reply(__u32 *reply_size)
{
	*reply_size = sizeof(struct m2p_execve_struct);
	return kmalloc(sizeof(struct m2p_execve_struct), GFP_KERNEL);
}

static int p2m_execve(struct p2m_execve_struct *payload,
		      struct m2p_execve_struct *reply,
		      __u32 payload_size, __u32 reply_size,
		      unsigned long *new_ip, unsigned long *new_sp)
{
	int ret;

	ret = net_send_reply_timeout(current_memory_home_node(), P2M_EXECVE, payload,
			payload_size, reply, reply_size, false, FIT_MAX_TIMEOUT_SEC);

	if (likely(ret > 0)) {
		if (likely(reply->status == RET_OKAY)) {
			*new_ip = reply->new_ip;
			*new_sp = reply->new_sp;
			return 0;
		} else {
			WARN(1, ret_to_string(reply->status));
			return -(reply->status);
		}
	}
	return ret;
}

/*
 * This function makes sure the current process has its own signal table,
 * so that flush_signal_handlers can later reset the handlers without
 * disturbing other processes.  (Other processes might share the signal
 * table via the CLONE_SIGHAND option to clone().)
 */
static int de_thread(struct task_struct *tsk)
{
	struct signal_struct *sig = tsk->signal;
	struct sighand_struct *oldsighand = tsk->sighand;
	spinlock_t *lock = &oldsighand->siglock;

	if (thread_group_empty(tsk))
		goto no_thread_group;

	/* Kill all other threads in the thread group */
	spin_lock_irq(lock);
	if (signal_group_exit(sig)) {
		/*
		 * Another group action in progress, just
		 * return so that the signal is processed.
		 */
		spin_unlock_irq(lock);
		return -EAGAIN;
	}

	sig->group_exit_task = tsk;
	sig->notify_count = zap_other_threads(tsk);
	if (!thread_group_leader(tsk))
		sig->notify_count--;

	while (sig->notify_count) {
		__set_current_state(TASK_KILLABLE);
		spin_unlock_irq(lock);
		schedule();
		if (unlikely(__fatal_signal_pending(tsk)))
			goto killed;
		spin_lock_irq(lock);
	}
	spin_unlock_irq(lock);

	/*
	 * At this point all other threads have exited, all we have to
	 * do is to wait for the thread group leader to become inactive,
	 * and to assume its PID:
	 */
	if (!thread_group_leader(tsk)) {
		struct task_struct *leader = tsk->group_leader;

		for (;;) {
			spin_lock_irq(&tasklist_lock);
			/*
			 * Do this under tasklist_lock to ensure that
			 * exit_notify() can't miss ->group_exit_task
			 */
			sig->notify_count = -1;
			if (likely(leader->exit_state))
				break;
			__set_current_state(TASK_KILLABLE);
			spin_unlock_irq(&tasklist_lock);
			schedule();
			if (unlikely(__fatal_signal_pending(tsk)))
				goto killed;
		}

		/*
		 * The only record we have of the real-time age of a
		 * process, regardless of execs it's done, is start_time.
		 * All the past CPU time is accumulated in signal_struct
		 * from sister threads now dead.  But in this non-leader
		 * exec, nothing survives from the original leader thread,
		 * whose birth marks the true age of this process now.
		 * When we take on its identity by switching to its PID, we
		 * also take its birthdate (always earlier than our own).
		 */
		tsk->start_time = leader->start_time;
		tsk->real_start_time = leader->real_start_time;

		BUG_ON(!same_thread_group(leader, tsk));
		BUG_ON(has_group_leader_pid(tsk));
		/*
		 * An exec() starts a new thread group with the
		 * TGID of the previous thread group. Rehash the
		 * two threads with a switched PID, and release
		 * the former thread group leader:
		 */

		BUG();
#if 0
		TODO
		/* Become a process group leader with the old leader's pid.
		 * The old leader becomes a thread of the this thread group.
		 * Note: The old leader also uses this pid until release_task
		 *       is called.  Odd but simple and correct.
		 */
		tsk->pid = leader->pid;
		change_pid(tsk, PIDTYPE_PID, task_pid(leader));
		transfer_pid(leader, tsk, PIDTYPE_PGID);
		transfer_pid(leader, tsk, PIDTYPE_SID);

		list_replace_rcu(&leader->tasks, &tsk->tasks);
		list_replace_init(&leader->sibling, &tsk->sibling);

		tsk->group_leader = tsk;
		leader->group_leader = tsk;

		tsk->exit_signal = SIGCHLD;
		leader->exit_signal = -1;

		BUG_ON(leader->exit_state != EXIT_ZOMBIE);
		leader->exit_state = EXIT_DEAD;

		spin_unlock_irq(&tasklist_lock);

		release_task(leader);
#endif
	}

	sig->group_exit_task = NULL;
	sig->notify_count = 0;

no_thread_group:
	/* we have changed execution domain */
	tsk->exit_signal = SIGCHLD;

	exit_itimers(sig);
	flush_itimer_signals();

	if (atomic_read(&oldsighand->count) != 1) {
		struct sighand_struct *newsighand;
		/*
		 * This ->sighand is shared with the CLONE_SIGHAND
		 * but not CLONE_THREAD task, switch to the new one.
		 */
		newsighand = kmalloc(sizeof(*newsighand), GFP_KERNEL);
		if (!newsighand)
			return -ENOMEM;

		atomic_set(&newsighand->count, 1);
		memcpy(newsighand->action, oldsighand->action,
		       sizeof(newsighand->action));

		spin_lock_irq(&tasklist_lock);
		spin_lock(&oldsighand->siglock);
		tsk->sighand = newsighand;
		spin_unlock(&oldsighand->siglock);
		spin_unlock_irq(&tasklist_lock);

		__cleanup_sighand(oldsighand);
	}

	BUG_ON(!thread_group_leader(tsk));
	return 0;

killed:
	/* protects against exit_notify() and __exit_signal() */
	spin_lock(&tasklist_lock);
	sig->group_exit_task = NULL;
	sig->notify_count = 0;
	spin_unlock(&tasklist_lock);

	return -EAGAIN;
}

static int flush_old_exec(void)
{
	int ret;

	/*
	 * Make sure we have a private signal table and that
	 * we are unassociated from the previous thread group.
	 */
	ret = de_thread(current);
	if (ret)
		goto out;

	/*
	 * Switch mm, to switch the emulated page-table
	 * User program also has its own one
	 */
	ret = exec_mmap();
	if (ret)
		goto out;

	/*
	 * THIS IS VERY IMPORTANT
	 * This thread is no longer a kernel thread. If this flag
	 * is not cleared, copy_process_tls() will falsely think
	 * this is a kernel thread if later on this guy calls sys_clone():
	 */
	current->flags &= ~(PF_KTHREAD | PF_NO_SETAFFINITY);
	flush_thread();

	/*
	 * We have to apply CLOEXEC before we change whether the process is
	 * dumpable (in setup_new_exec) to avoid a race with a process in userspace
	 * trying to access the should-be-closed file descriptors of a process
	 * undergoing exec(2).
	 */
	do_close_on_exec(current->files);

	ret = 0;
out:
	return ret;
}

static void setup_new_exec(const char *filename)
{
	/* This is the point of no return */
	current->sas_ss_sp = current->sas_ss_size = 0;

	set_task_comm(current, kbasename(filename));

	/*
	 * An exec changes our domain.
	 * We are no longer part of the thread group:
	 */
	current->self_exec_id++;
	flush_signal_handlers(current, 0);
}

int do_execve(const char __user *filename,
	      const char __user * const * __user argv,
	      const char __user * const * __user envp)
{
	int ret;
	__u32 payload_size, reply_size;
	unsigned long new_ip, new_sp;
	struct pt_regs *regs = current_pt_regs();
	void *payload, *reply;

	payload = prepare_exec_payload(filename, argv, envp, &payload_size);
	if (IS_ERR(payload))
		return PTR_ERR(payload);

	reply = prepare_exec_reply(&reply_size);
	if (!reply) {
		kfree(payload);
		return -ENOMEM;
	}

	ret = p2m_execve(payload, reply, payload_size, reply_size,
			 &new_ip, &new_sp);
	if (ret)
		goto out;

	ret = flush_old_exec();
	if (ret)
		goto out;

#ifdef CONFIG_DISTRIBUTED_VMA_PROCESSOR
	map_mnode_from_reply(current->mm,
			   &((struct m2p_execve_struct *)reply)->map);
#endif

	/*
	 * Use the f_name saved in payload
	 * to save one extra strncpy_from_user
	 */
	setup_new_exec(((struct p2m_execve_struct *)payload)->filename);

#ifdef ELF_PLAT_INIT
	/*
	 * The ABI may specify that certain registers be set up in special
	 * ways (on i386 %edx is the address of a DT_FINI function, for
	 * example.  In addition, it may also specify (eg, PowerPC64 ELF)
	 * that the e_entry field is the address of the function descriptor
	 * for the startup routine, rather than the address of the startup
	 * routine itself.  This macro performs whatever initialization to
	 * the regs structure is required as well as any relocations to the
	 * function descriptor entries when executing dynamically links apps.
	 */
	ELF_PLAT_INIT(regs);
#endif

	/* core-kernel: change the task iret frame */
	start_thread(regs, new_ip, new_sp);
	ret = 0;

out:
	kfree(payload);
	kfree(reply);

	/*
	 * This return will return to the point where do_execve()
	 * is invoked. The final return to user-space will happen
	 * when this kernel thread finishes and merges into
	 * the end of ret_from_fork().
	 *
	 * Check ret_from_fork() for more detail.
	 */
	return ret;
}

SYSCALL_DEFINE3(execve,
		const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp)
{
	return do_execve(filename, argv, envp);
}
