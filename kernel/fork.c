/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/pid.h>
#include <lego/slab.h>
#include <lego/files.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/syscalls.h>
#include <lego/fit_ibapi.h>
#include <lego/timekeeping.h>
#include <lego/comp_processor.h>

#include <asm/pgalloc.h>

/* Initialized by the architecture: */
int arch_task_struct_size __read_mostly = sizeof(struct task_struct);

DEFINE_SPINLOCK(tasklist_lock);
unsigned long total_forks;
int nr_threads;			/* The idle threads do not count.. */

static inline struct task_struct *alloc_task_struct_node(int node)
{
	return kmalloc(arch_task_struct_size, GFP_KERNEL);
}

static inline void free_task_struct(struct task_struct *tsk)
{
	kfree(tsk);
}

static inline unsigned long *
alloc_thread_stack_node(struct task_struct *tsk, int node)
{
	struct page *page;

	page = alloc_pages_node(node, GFP_KERNEL, THREAD_SIZE_ORDER);
	return page ? page_address(page) : NULL;
}

static inline void free_thread_stack(struct task_struct *tsk)
{
	__free_pages(virt_to_page(tsk->stack), THREAD_SIZE_ORDER);
}

/*
 * Setup stack end magic number
 * for overflow detection
 */
void setup_task_stack_end_magic(struct task_struct *tsk)
{
	unsigned long *stackend;

	stackend = end_of_stack(tsk);
	*stackend = STACK_END_MAGIC;
}

void __put_task_struct(struct task_struct *tsk)
{
	WARN_ON(atomic_read(&tsk->usage));
	WARN_ON(tsk == current);
}

/*
 * Duplicate a new task_struct based on parent task_struct.
 * Allocate a new kernel stack and setup stack_info to make current work.
 */
static struct task_struct *dup_task_struct(struct task_struct *old, int node)
{
	struct task_struct *new;
	unsigned long *stack;
	int err;

	new = alloc_task_struct_node(node);
	if (!new)
		return NULL;

	stack = alloc_thread_stack_node(new, node);
	if (!stack)
		goto free_task;

	err = arch_dup_task_struct(new, old);

	/*
	 * arch_dup_task_struct() clobbers the stack-related fields.
	 * Make sure they're properly initialized before using any
	 * stack-related functions again.
	 */
	new->stack = stack;
	if (err)
		goto free_stack;

	/* Duplicate whole stack! */
	*task_thread_info(new) = *task_thread_info(old);

	/* Make current macro work */
	task_thread_info(new)->task = new;
	clear_tsk_need_resched(new);
	setup_task_stack_end_magic(new);

	/*
	 * One for us,
	 * one for whoever does the "release_task()" (usually parent)
	 */
	atomic_set(&new->usage, 2);

	return new;

free_stack:
	free_thread_stack(new);
free_task:
	free_task_struct(new);
	return NULL;
}

static void free_task(struct task_struct *tsk)
{
	if (WARN_ON(tsk->state != TASK_DEAD))
		return;

	free_thread_stack(tsk);
	tsk->stack = NULL;
	free_task_struct(tsk);
}

static inline void mm_free_pgd(struct mm_struct *mm)
{
	pgd_free(mm, mm->pgd);
}

static inline void __mmput(struct mm_struct *mm)
{
	BUG_ON(atomic_read(&mm->mm_users));
	BUG_ON(mm == &init_mm);

	mm_free_pgd(mm);
	kfree(mm);
}

/*
 * Decrement the use count and release all resources for an mm
 * if this is the last user.
 */
void mmput(struct mm_struct *mm)
{
	if (atomic_dec_and_test(&mm->mm_users))
		__mmput(mm);
}

/* Please note the differences between mmput and mm_release.
 * mmput is called whenever we stop holding onto a mm_struct,
 * error success whatever.
 *
 * mm_release is called after a mm_struct has been removed
 * from the current process.
 *
 * This difference is important for error handling, when we
 * only half set up a mm_struct for a new process and need to restore
 * the old one.  Because we mmput the new mm_struct before
 * restoring the old one. . .
 * Eric Biederman 10 January 1998
 */
void mm_release(struct task_struct *tsk, struct mm_struct *mm)
{
	/* Get rid of any cached register state */
	deactivate_mm(tsk, mm);
}

static struct mm_struct *mm_init(struct mm_struct *mm, struct task_struct *p)
{
	atomic_set(&mm->mm_users, 1);
	atomic_set(&mm->mm_count, 1);
	mm->map_count = 0;
	mm->pinned_vm = 0;
	spin_lock_init(&mm->page_table_lock);

	/*
	 * pgd_alloc() will duplicate the identity kernel mapping
	 * but leaves other entries empty:
	 */
	mm->pgd = pgd_alloc(mm);
	if (unlikely(!mm->pgd)) {
		kfree(mm);
		return NULL;
	}
	return mm;
}

/*
 * Allocate and initialize an mm_struct.
 */
struct mm_struct *mm_alloc(void)
{
	struct mm_struct *mm;

	mm = kmalloc(sizeof(*mm), GFP_KERNEL);
	if (!mm)
		return NULL;

	memset(mm, 0, sizeof(*mm));
	return mm_init(mm, current);
}

static struct mm_struct *dup_mm_struct(struct task_struct *tsk)
{
	struct mm_struct *mm, *oldmm;

	oldmm = current->mm;

	mm = kmalloc(sizeof(*mm), GFP_KERNEL);
	if (!mm)
		return NULL;

	memcpy(mm, oldmm, sizeof(*mm));

	if (!mm_init(mm, tsk))
		return NULL;

	return mm;
}

/*
 * mm_struct does not handle user virtual memory
 * so no need to copy all mmap:
 */
static int copy_mm(unsigned long clone_flags, struct task_struct *tsk)
{
	struct mm_struct *mm, *oldmm;

	tsk->mm = tsk->active_mm = NULL;
	tsk->nvcsw = tsk->nivcsw = 0;

	oldmm = current->mm;
	if (clone_flags & CLONE_VM) {
		atomic_inc(&oldmm->mm_users);
		mm = oldmm;
		goto good_mm;
	}

	mm = dup_mm_struct(tsk);
	if (!mm)
		return -ENOMEM;

good_mm:
	tsk->mm = mm;
	tsk->active_mm = mm;

	return 0;
}

static void put_files_struct(struct files_struct *files)
{
	if (atomic_dec_and_test(&files->count)) {
		/* TODO: put files */
		kfree(files);
	}
}

static void exit_files(struct task_struct *tsk)
{
	struct files_struct * files = tsk->files;

	if (files) {
		task_lock(tsk);
		tsk->files = NULL;
		task_unlock(tsk);
		put_files_struct(files);
	}
}

static struct files_struct *dup_fd(struct files_struct *oldf)
{
	struct files_struct *newf;

	newf = kmalloc(sizeof(*newf), GFP_KERNEL);
	if (!newf)
		return NULL;

	atomic_set(&newf->count, 1);
	spin_lock_init(&newf->file_lock);

	/* Copy the content */
	spin_lock(&oldf->file_lock);
	/* TODO: get_file */
	spin_unlock(&oldf->file_lock);

	return newf;
}

static int copy_files(unsigned long clone_flags, struct task_struct *tsk)
{
	struct files_struct *oldf, *newf;
	int ret = 0;

	oldf = tsk->files;
	if (clone_flags & CLONE_FILES) {
		newf = oldf;
		atomic_inc(&oldf->count);
		goto out;
	}

	newf = dup_fd(oldf);
	if (!newf) {
		ret = -ENOMEM;
		goto out;
	}

	tsk->files = newf;
	ret = 0;

out:
	return ret;
}

static int copy_sighand(unsigned long clone_flags, struct task_struct *tsk)
{
	return 0;
}

void __cleanup_sighand(struct sighand_struct *sighand)
{
}

static int copy_signal(unsigned long clone_flags, struct task_struct *tsk)
{
	return 0;
}

static inline void free_signal_struct(struct signal_struct *sig)
{
}

/*
 * This creates a new process as a copy of the old one,
 * but does not actually start it yet.
 *
 * It copies the registers, and all the appropriate
 * parts of the process environment (as per the clone
 * flags). The actual kick-off is left to the caller.
 */
struct task_struct *copy_process(unsigned long clone_flags,
				 unsigned long stack_start,
				 unsigned long stack_size,
				 int __user *child_tidptr,
				 unsigned long tls, int node)
{
	struct task_struct *p;
	int retval;
	int pid = 0;
	unsigned long flags;

	/*
	 * Thread groups must share signals as well, and detached threads
	 * can only be started up within the thread group.
	 */
	if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
		return ERR_PTR(-EINVAL);

	/*
	 * Shared signal handlers imply shared VM. By way of the above,
	 * thread groups also imply shared VM. Blocking this case allows
	 * for various simplifications in other code.
	 */
	if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
		return ERR_PTR(-EINVAL);

	/* Duplicate task_struct and create new stack */
	p = dup_task_struct(current, node);
	if (!p)
		return ERR_PTR(-ENOMEM);

	p->flags &= ~(PF_SUPERPRIV | PF_WQ_WORKER | PF_IDLE);
	p->flags |= PF_FORKNOEXEC;
	INIT_LIST_HEAD(&p->children);
	INIT_LIST_HEAD(&p->sibling);
	INIT_LIST_HEAD(&p->thread_group);
	p->vfork_done = NULL;
	spin_lock_init(&p->alloc_lock);

	init_sigpending(&p->pending);

	p->utime = p->stime = p->gtime = 0;
	p->start_time = ktime_get_ns();
	p->real_start_time = ktime_get_boot_ns();

	/* Perform scheduler related setup. Assign this task to a CPU. */
	retval = setup_sched_fork(clone_flags, p);
	if (retval)
		goto out_free;

	retval = copy_files(clone_flags, p);
	if (retval)
		goto out_cleanup_sched;

	retval = copy_sighand(clone_flags, p);
	if (retval)
		goto out_cleanup_files;

	retval = copy_signal(clone_flags, p);
	if (retval)
		goto out_cleanup_sighand;

	retval = copy_mm(clone_flags, p);
	if (retval)
		goto out_cleanup_signal;

	retval = copy_thread_tls(clone_flags, stack_start, stack_size, p, tls);
	if (retval)
		goto out_cleanup_mm;

	/* clone idle thread, whose pid is 0 */
	if (!(clone_flags & CLONE_IDLE_THREAD)) {
		pid = alloc_pid(p);
		if (!pid)
			goto out_cleanup_thread;
	}

	p->set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ? child_tidptr : NULL;
	/*
	 * Clear TID on mm_release()?
	 */
	p->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ? child_tidptr : NULL;

	/* ok, now we should be set up.. */
	p->pid = pid;
	if (clone_flags & CLONE_THREAD) {
		p->exit_signal = -1;
		p->group_leader = current->group_leader;
		p->tgid = current->tgid;
	} else {
		if (clone_flags & CLONE_PARENT)
			p->exit_signal = current->group_leader->exit_signal;
		else
			p->exit_signal = (clone_flags & CSIGNAL);
		p->group_leader = p;
		p->tgid = p->pid;
	}

	/*
	 * Make it visible to the rest of the system, but dont wake it up yet.
	 * Need tasklist lock for parent etc handling!
	 */
	spin_lock_irqsave(&tasklist_lock, flags);

	/* CLONE_PARENT re-uses the old parent */
	if (clone_flags & (CLONE_PARENT|CLONE_THREAD)) {
		p->real_parent = current->real_parent;
		p->parent_exec_id = current->parent_exec_id;
	} else {
		p->real_parent = current;
		p->parent_exec_id = current->self_exec_id;
	}

	if (likely(p->pid)) {
		if (thread_group_leader(p)) {
			p->signal->leader_pid = pid;
			list_add_tail(&p->sibling, &p->real_parent->children);
			list_add_tail(&p->tasks, &init_task.tasks);
		} else {
			current->signal->nr_threads++;
			atomic_inc(&current->signal->live);
			atomic_inc(&current->signal->sigcnt);
			list_add_tail(&p->thread_group,
					  &p->group_leader->thread_group);
			list_add_tail(&p->thread_node,
					  &p->signal->thread_head);
		}
		nr_threads++;
	}

	total_forks++;
	spin_unlock_irqrestore(&tasklist_lock, flags);

	return p;

out_cleanup_thread:
	exit_thread(p);
out_cleanup_mm:
	if (p->mm)
		mmput(p->mm);
out_cleanup_signal:
	if (!(clone_flags & CLONE_THREAD))
		free_signal_struct(p->signal);
out_cleanup_sighand:
	__cleanup_sighand(p->sighand);
out_cleanup_files:
	exit_files(p);
out_cleanup_sched:
	sched_remove_from_rq(p);
out_free:
	p->state = TASK_DEAD;
	free_task(p);
	free_pid(pid);

	return ERR_PTR(retval);;
}

/* Well, Lego's main fork-routine */
pid_t do_fork(unsigned long clone_flags,
	      unsigned long stack_start,
	      unsigned long stack_size,
	      int __user *parent_tidptr,
	      int __user *child_tidptr,
	      int tls)
{
	struct task_struct *p;

	p = copy_process(clone_flags, stack_start, stack_size,
			 child_tidptr, tls, NUMA_NO_NODE);
	if (IS_ERR(p))
		return PTR_ERR(p);

#ifdef CONFIG_COMP_PROCESSOR
	if (clone_flags & CLONE_GLOBAL_THREAD) {
		int ret;

		ret = p2m_fork(p, clone_flags);
		if (ret) {
			/* TODO: free task_struct */
			return ret;
		}
	}
#endif

	wake_up_new_task(p);
	return p->pid;
}

/**
 * kernel_thread	-	Create a kernel thread
 * @fn: the function to run in the thread
 * @arg: data pointer for @fn()
 * @flags: CLONE flags
 *
 * Create a new kernel thread and put it to run.
 * Return the pid of newly created thread on success.
 */
pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags)
{
	return do_fork(flags|CLONE_VM, (unsigned long)fn, (unsigned long)arg,
		       NULL, NULL, 0);
}

SYSCALL_DEFINE0(fork)
{
	return do_fork(SIGCHLD, 0, 0, NULL, NULL, 0);
}

SYSCALL_DEFINE0(vfork)
{
	return do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD,
		       0, 0, NULL, NULL, 0);
}

SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,
		 int __user *, parent_tidptr,
		 int __user *, child_tidptr,
		 unsigned long, tls)
{
	return do_fork(clone_flags, newsp, 0, parent_tidptr, child_tidptr, tls);
}

void __init fork_init(void)
{
	pr_info("fork: arch_task_struct_size: %d, task_struct: %lu\n",
		arch_task_struct_size, sizeof(struct task_struct));
}
