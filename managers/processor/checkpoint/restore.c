/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/pid.h>
#include <lego/timer.h>
#include <lego/ktime.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/kthread.h>
#include <lego/spinlock.h>
#include <lego/completion.h>
#include <lego/checkpoint.h>
#include <processor/fs.h>

#include <asm/prctl.h>
#include <asm/fpu/internal.h>

#include "internal.h"

static LIST_HEAD(restorer_work_list);
static DEFINE_SPINLOCK(restorer_work_lock);
static struct task_struct *restorer_worker;

struct restorer_work_info {
	/* Info passed to restorer from restore_process_snapshot() */
	struct process_snapshot	*pss;

	/* Results passed back to restore_process_snapshot() from restorer */
	struct task_struct	*result;
	struct completion	*done;

	struct list_head	list;
};

/* It is really just a copy of sys_open() */
static int restore_sys_open(struct ss_files *ss_f)
{
	struct file *f;
	int fd, ret;
	char *f_name = ss_f->f_name;

	fd = alloc_fd(current->files, f_name);
	if (unlikely(fd != ss_f->fd)) {
		pr_err("Unmactched fd: %d:%s\n",
			ss_f->fd, ss_f->f_name);
		return -EBADF;
	}

	f = fdget(fd);
	f->f_flags = ss_f->f_flags;
	f->f_mode = ss_f->f_mode;

	if (unlikely(proc_file(f_name)))
		ret = proc_file_open(f, f_name);
	else if (unlikely(sys_file(f_name)))
		ret = sys_file_open(f, f_name);
	else
		ret = normal_file_open(f, f_name);

	if (ret) {
		free_fd(current->files, fd);
		goto put;
	}

	BUG_ON(!f->f_op->open);
	ret = f->f_op->open(f);
	if (ret)
		free_fd(current->files, fd);

put:
	put_file(f);
	return ret;
}

static int restore_open_files(struct process_snapshot *pss)
{
	unsigned int nr_files = pss->nr_files;
	struct files_struct *files = current->files;
	int fd, ret;
	struct file *f;
	struct ss_files *ss_f;

	for (fd = 0; fd < nr_files; fd++) {
		ss_f = &pss->files[fd];

		/*
		 * TODO
		 * Currently, Lego always open the 3 default
		 * STDIN, STDOUT, STDERR for newly created
		 * processes. But it may close the fd during
		 * runtime.. If so, we need to handle this.
		 */
		if (fd < 3 && test_bit(fd, files->fd_bitmap)) {
			f = files->fd_array[fd];
			BUG_ON(!f);

			if (strncmp(ss_f->f_name, f->f_name,
				FILENAME_LEN_DEFAULT)) {
				WARN(1, "Pacth needed here!");
				ret = -EBADF;
				goto out;
			}
			continue;
		}

		ret = restore_sys_open(ss_f);
		if (ret)
			goto out;
	}

out:
	return ret;
}

static void restore_signals(struct process_snapshot *pss)
{
	struct k_sigaction *k_action = current->sighand->action;
	struct sigaction *src, *dst;
	int i;

	for (i = 0; i < _NSIG; i++) {
		src = &pss->action[i];
		dst = &k_action[i].sa;
		memcpy(dst, src, sizeof(*dst));
	}

	memcpy(&current->blocked, &pss->blocked, sizeof(sigset_t));
}

/*
 * Restore per-thread state
 * 1) Some thread data fields inside task_struct
 * 2) the top pt_regs used to return to user-program
 * 3) fsbase and gsbase
 */
static void restore_thread_state(struct task_struct *p,
				 struct ss_task_struct *ss_task)
{
	struct pt_regs *dst = task_pt_regs(p);
	struct ss_thread_gregs *src = &(ss_task->user_regs.gregs);

	p->set_child_tid = ss_task->set_child_tid;
	p->clear_child_tid = ss_task->clear_child_tid;
	p->sas_ss_sp = ss_task->sas_ss_sp;
	p->sas_ss_size = ss_task->sas_ss_size;
	p->sas_ss_flags = ss_task->sas_ss_flags;

#define RESTORE_REG(reg)	do { dst->reg = src->reg; } while (0)
	RESTORE_REG(r15);
	RESTORE_REG(r14);
	RESTORE_REG(r13);
	RESTORE_REG(r12);
	RESTORE_REG(bp);
	RESTORE_REG(bx);
	RESTORE_REG(r11);
	RESTORE_REG(r10);
	RESTORE_REG(r9);
	RESTORE_REG(r8);
	RESTORE_REG(ax);
	RESTORE_REG(cx);
	RESTORE_REG(dx);
	RESTORE_REG(si);
	RESTORE_REG(di);
	RESTORE_REG(orig_ax);
	RESTORE_REG(ip);
	RESTORE_REG(cs);
	RESTORE_REG(flags);
	RESTORE_REG(sp);
	RESTORE_REG(ss);
#undef RESTORE_REG

	if (src->fs_base)
		do_arch_prctl(p, ARCH_SET_FS, src->fs_base);
	if (src->gs_base)
		do_arch_prctl(p, ARCH_SET_GS, src->gs_base);
}

struct wait_info {
	struct ss_task_struct	*ss_task;
	struct completion	done;
};

static int restorer_for_other_threads(void *_wait)
{
	struct wait_info *wait = _wait;
	struct ss_task_struct *ss_task = wait->ss_task;

	restore_thread_state(current, ss_task);

	chk_debug("%s(): %d-%d waiting\n", FUNC, current->pid, current->tgid);
	wait_for_completion(&wait->done);

	/* Return to user-space */
	return 0;
}

static void restore_thread_group(struct restorer_work_info *info)
{
	struct process_snapshot *pss = info->pss;
	struct ss_task_struct *ss_task, *ss_tasks = pss->tasks;
	struct task_struct *t;
	struct wait_info *wait;
	unsigned long clone_flags;
	int nr_threads = pss->nr_tasks;
	int i;

	ss_task = &ss_tasks[0];
	restore_thread_state(current, ss_task);

	if (nr_threads == 1)
		goto done;

	wait = kmalloc(nr_threads * sizeof(*wait), GFP_KERNEL);
	if (!wait) {
		info->result = ERR_PTR(-ENOMEM);
		return;
	}

	clone_flags = CLONE_THREAD | CLONE_SIGHAND |
		      CLONE_VM | CLONE_FILES | CLONE_PARENT;

	/* Restore other threads in group */
	for (i = 1; i < nr_threads; i++) {
		ss_task = &ss_tasks[i];
		wait[i].ss_task = ss_task;
		init_completion(&wait[i].done);

		t = copy_process(clone_flags,
				(unsigned long)restorer_for_other_threads,
				(unsigned long)&wait[i], NULL, 0, NUMA_NO_NODE);
		if (IS_ERR(t)) {
			WARN_ON(1);
			info->result = t;
			return;
		}

		wake_up_new_task(t);
	}

	kfree(wait);
done:
	/* Return leader's task struct back to caller */
	info->result = current;
}

static int restorer_for_group_leader(void *_info)
{
	struct restorer_work_info *info = _info;
	struct process_snapshot *pss = info->pss;

#ifdef CONFIG_DEBUG_CHECKPOINT
	dump_task_struct(current, 0);
	dump_process_snapshot(pss, "Restorer", 0);
#endif

	/* Fisrt, restore thread group shared data */
	memcpy(current->comm, pss->comm, TASK_COMM_LEN);
	restore_open_files(pss);
	restore_signals(pss);

	/* Create other threads in group */
	restore_thread_group(info);
	if (IS_ERR(info->result))
		goto err;

#ifdef CONFIG_DEBUG_CHECKPOINT
	dump_task_struct(current, 0);
#endif

	/* Release restore_process_snapshot() */
	complete(info->done);

	/* Return to user-space */
	return 0;

err:
	complete(info->done);
	do_exit(-1);
	BUG();
	return 0;
}

static void create_restorer(struct restorer_work_info *info)
{
	int pid;

	/*
	 * Use do_fork() instead of kernel_thread() because
	 * we need a private mm:
	 */
	pid = do_fork(SIGCHLD, (unsigned long)restorer_for_group_leader,
			(unsigned long)info, NULL, NULL, 0);
	if (pid < 0) {
		WARN_ON_ONCE(1);
		info->result = ERR_PTR(pid);

		/* Release restore_process_snapshot() */
		complete(info->done);
	}
}

/*
 * It dequeue work from work_list, and creates a restorer to construct
 * a new process from snapshot. Any error is reported by restorer in
 * the info->result field.
 */
int restorer_worker_thread(void *unused)
{
	set_cpus_allowed_ptr(current, cpu_possible_mask);

	for (;;) {
		/* Sleep until someone wakes me up before september ends */
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (list_empty(&restorer_work_list))
			schedule();
		__set_current_state(TASK_RUNNING);

		spin_lock(&restorer_work_lock);
		while (!list_empty(&restorer_work_list)) {
			struct restorer_work_info *info;

			info = list_entry(restorer_work_list.next,
					struct restorer_work_info, list);
			list_del_init(&info->list);

			/*
			 * Release the lock so others can attach work.
			 * The real work may take some time.
			 */
			spin_unlock(&restorer_work_lock);

			create_restorer(info);

			spin_lock(&restorer_work_lock);
		}
		spin_unlock(&restorer_work_lock);
	}

	return 0;
}

/**
 * restore_process_snapshot	-	Restore a process from snapshot
 * @pss: the snapshot
 *
 * This function is synchronized. It will wait until the new process
 * is live from the snapshot. The real work of restoring is done by
 * restorer worker thread.
 *
 * Return the task_struct of new thread-group leader.
 * On failure, ERR_PTR is returned.
 */
struct task_struct *restore_process_snapshot(struct process_snapshot *pss)
{
	DEFINE_COMPLETION(done);
	struct restorer_work_info info;
	struct task_struct *result;

	/*
	 * Note:
	 * If we decide to make this function a-sync later,
	 * we need to allocate info instead of using stack.
	 */
	info.pss = pss;
	info.done = &done;

	spin_lock(&restorer_work_lock);
	list_add_tail(&info.list, &restorer_work_list);
	spin_unlock(&restorer_work_lock);

	wake_up_process(restorer_worker);
	wait_for_completion(&done);

	result = info.result;

	pr_debug("%s(): restored task: %d comm:%s\n",
		FUNC, result->pid, result->comm);
	return result;
}

void __init checkpoint_init(void)
{
	restorer_worker = kthread_run(restorer_worker_thread, NULL, "krestorerd");
	if (IS_ERR(restorer_worker))
		panic("Fail to create checkpointing restore thread!");
}
