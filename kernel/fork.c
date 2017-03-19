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
#include <lego/sched.h>
#include <lego/kernel.h>

#include <asm/pgalloc.h>

static inline struct task_struct *alloc_task_struct_node(int node)
{
	return kmalloc(GFP_KERNEL, sizeof(struct task_struct));
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

	new = alloc_task_struct_node(node);
	if (!new)
		return NULL;

	stack = alloc_thread_stack_node(new, node);
	if (!stack)
		goto free_task;

	*new = *old;

	new->stack = stack;
	*task_thread_info(new) = *task_thread_info(old);

	/* Make current macro work */
	task_thread_info(new)->task = new;
	setup_task_stack_end_magic(new);

	return new;

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

/* TODO: cleanup all mm_struct related stuff */
static inline void __mmput(struct mm_struct *mm)
{
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

/* TODO: copy mmap for the new mm */
static int dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm)
{
	return 0;
}

static int mm_init(struct mm_struct *mm, struct task_struct *p)
{
	mm->mmap = NULL;
	atomic_set(&mm->mm_users, 1);
	atomic_set(&mm->mm_count, 1);
	mm->map_count = 0;
	mm->pinned_vm = 0;
	spin_lock_init(&mm->page_table_lock);

	mm->pgd = pgd_alloc(mm);
	if (!mm->pgd)
		goto out;

	return 0;

out:
	kfree(mm);
	return -ENOMEM;
}

static struct mm_struct *dup_mm_struct(struct task_struct *tsk)
{
	struct mm_struct *mm, *oldmm;
	int ret;

	oldmm = current->mm;

	mm = kmalloc(GFP_KERNEL, sizeof(*mm));
	if (!mm)
		return NULL;

	*mm = *oldmm;

	ret = mm_init(mm, tsk);
	if (ret)
		return NULL;

	ret = dup_mmap(mm, oldmm);
	if (ret)
		goto out;

	return mm;

out:
	mmput(mm);
	return NULL;
}

static int copy_mm(unsigned long clone_flags, struct task_struct *tsk)
{
	struct mm_struct *mm, *oldmm;

	tsk->mm = NULL;
	tsk->active_mm = NULL;

	/*
	 * Are we cloning a kernel thread?
	 *
	 * We need to steal a active VM for that..
	 */
	oldmm = current->mm;
	if (!oldmm)
		return 0;

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

struct task_struct *copy_process(unsigned long clone_flags,
				 unsigned long stack_start,
				 unsigned long stack_size,
				 int node, int tls)
{
	struct task_struct *p;
	int retval;
	int pid;

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

	/*
	 * Setup scheduler:
	 * assign this task to a CPU
	 */
	retval = setup_sched_fork(clone_flags, p);
	if (retval)
		goto out_free;

	/* Duplicate mm_struct and create new pgd */
	retval = copy_mm(clone_flags, p);
	if (retval)
		goto out_cleanup_sched;

	retval = copy_thread_tls(clone_flags, stack_start, stack_size, p, tls);
	if (retval)
		goto out_cleanup_mm;

	pid = alloc_pid(p);
	if (!pid)
		goto out_cleanup_thread;

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

	/* CLONE_PARENT re-uses the old parent */
	if (clone_flags & (CLONE_PARENT|CLONE_THREAD)) {
		p->real_parent = current->real_parent;
	} else {
		p->real_parent = current;
	}

	return p;

	free_pid(pid);
out_cleanup_thread:
out_cleanup_mm:
	if (p->mm)
		mmput(p->mm);
out_cleanup_sched:
	sched_remove_from_rq(p);
out_free:
	p->state = TASK_DEAD;
	free_task(p);

	return ERR_PTR(retval);;
}

pid_t do_fork(unsigned long clone_flags,
	      unsigned long stack_start,
	      unsigned long stack_size,
	      int tls)
{
	struct task_struct *p;

	p = copy_process(clone_flags, stack_start, stack_size, NUMA_NO_NODE, tls);
	if (IS_ERR(p))
		return PTR_ERR(p);

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
	return do_fork(flags | CLONE_VM, (unsigned long)fn, (unsigned long)arg, 0);
}
