/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/sched.h>
#include <lego/kernel.h>

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
	task_thread_info(new)->task = new;
	setup_task_stack_end_magic(new);

	return new;

free_task:
	free_task_struct(new);
	return NULL;
}

static struct task_struct *copy_process(unsigned long clone_flags,
					unsigned long stack_start,
					unsigned long stack_size,
					int node)
{
	struct task_struct *p;

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

	p = dup_task_struct(current, node);
	if (!p)
		return ERR_PTR(-ENOMEM);

	return p;
}

pid_t do_fork(unsigned long clone_flags,
	      unsigned long stack_start,
	      unsigned long stack_size)
{
	struct task_struct *p;
	pid_t pid = 0;

	p = copy_process(clone_flags, stack_start, stack_size, NUMA_NO_NODE);

	return pid;
}

/**
 * kernel_thread	-	Create a kernel thread
 * @fn:
 * @arg:
 * @flags:
 *
 * Return the pid of newly created thread on success.
 */
pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags)
{
	return do_fork(flags | CLONE_VM, (unsigned long)fn, (unsigned long)arg);
}
