/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/slab.h>
#include <lego/fit_ibapi.h>
#include <lego/comp_memory.h>

#include <memory/include/vm.h>
#include <memory/include/pid.h>

struct lego_task_struct init_lego_task = {
	.tasks		=	LIST_HEAD_INIT(init_lego_task.tasks),
	.real_parent	=	&init_lego_task,
	.parent		=	&init_lego_task,
	.children	=	LIST_HEAD_INIT(init_lego_task.children),
	.sibling	=	LIST_HEAD_INIT(init_lego_task.sibling),
};

static int copy_sighand(unsigned int clone_flags, struct lego_task_struct *new,
			struct lego_task_struct *old)
{
	if (clone_flags & CLONE_SIGHAND) {
		/* inc refcount of old->sig */
	}
	/* otherwise, allocate new */

	return 0;
}

static int copy_signal(unsigned int clone_flags, struct lego_task_struct *new,
		       struct lego_task_struct *old)
{
	return 0;
}

static int dup_lego_mmap(struct lego_mm_struct *mm,
			 struct lego_mm_struct *oldmm)
{
	struct vm_area_struct *mpnt, *tmp, *prev, **pprev;
	struct rb_node **rb_link, *rb_parent;
	int retval;

	if (down_write_killable(&mm->mmap_sem))
		return -EINTR;

	mm->total_vm = oldmm->total_vm;
	mm->data_vm = oldmm->data_vm;
	mm->exec_vm = oldmm->exec_vm;
	mm->stack_vm = oldmm->stack_vm;

	rb_link = &mm->mm_rb.rb_node;
	rb_parent = NULL;
	pprev = &mm->mmap;

	prev = NULL;
	for (mpnt = oldmm->mmap; mpnt; mpnt = mpnt->vm_next) {
		struct lego_file *file;

		tmp = kzalloc(sizeof(*tmp), GFP_KERNEL);
		if (!tmp)
			goto fail_nomem;
		*tmp = *mpnt;
		INIT_LIST_HEAD(&tmp->anon_vma_chain);
		tmp->vm_mm = mm;
		tmp->vm_flags &=
			~(VM_LOCKED|VM_LOCKONFAULT|VM_UFFD_MISSING|VM_UFFD_WP);
		tmp->vm_next = tmp->vm_prev = NULL;

		file = tmp->vm_file;
		if (file) {
			/* Possible TODO */
		}

		/*
		 * Link in the new vma and copy the page table entries.
		 */
		*pprev = tmp;
		pprev = &tmp->vm_next;
		tmp->vm_prev = prev;
		prev = tmp;

		__vma_link_rb(mm, tmp, rb_link, rb_parent);
		rb_link = &tmp->vm_rb.rb_right;
		rb_parent = &tmp->vm_rb;

		mm->map_count++;
		retval = copy_page_range(mm, oldmm, mpnt);

		if (tmp->vm_ops && tmp->vm_ops->open)
			tmp->vm_ops->open(tmp);

		if (retval)
			goto out;
	}

	retval = 0;
out:
	up_write(&mm->mmap_sem);
	return retval;

fail_nomem:
	retval = -ENOMEM;
	goto out;
}

/*
 * Allocate a new mm structure and copy contents from the
 * mm structure of the passed in task structure.
 */
static struct lego_mm_struct *
dup_lego_mm(struct lego_task_struct *new, struct lego_task_struct *old)
{
	struct lego_mm_struct *mm;
	struct lego_mm_struct *oldmm = NULL;
	int err;

	mm = kzalloc(sizeof(*mm), GFP_KERNEL);
	if (!mm)
		return NULL;

	if (old) {
		oldmm = old->mm;
		memcpy(mm, oldmm, sizeof(*mm));
	}

	/*
	 * Reset almost all variables
	 * and allocate a new pgd
	 */
	if (!lego_mm_init(mm, new))
		return NULL;

	if (oldmm) {
		err = dup_lego_mmap(mm, oldmm);
		if (err)
			goto free_pt;
	}

	return mm;

free_pt:
	lego_mmput(mm);
	return NULL;
}

static int copy_lego_mm(unsigned int clone_flags, struct lego_task_struct *new,
			struct lego_task_struct *old)
{
	struct lego_mm_struct *mm;

	if (clone_flags & CLONE_VM) {
		mm = old->mm;
		atomic_inc(&mm->mm_users);
		goto good_mm;
	}

	mm = dup_lego_mm(new, old);
	if (!mm)
		return -ENOMEM;

good_mm:
	new->mm = mm;

	return 0;
}

/**
 * Similar to copy_process(), init a new lego task struct.
 * and its lego mm struct.
 */
static int alloc_lego_task(struct lego_task_struct *new,
			   struct lego_task_struct *current_tsk,
			   unsigned int clone_flags)
{
	int ret;

	BUG_ON(!new);

	/*
	 * Thread groups must share signals as well, and detached threads
	 * can only be started up within the thread group.
	 */
	if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
		return -EINVAL;

	/*
	 * Shared signal handlers imply shared VM. By way of the above,
	 * thread groups also imply shared VM. Blocking this case allows
	 * for various simplifications in other code.
	 */
	if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
		return -EINVAL;

	INIT_LIST_HEAD(&new->children);
	INIT_LIST_HEAD(&new->sibling);
	INIT_LIST_HEAD(&new->thread_group);
	spin_lock_init(&new->task_lock);

	/*
	 * new is thread_group leader
	 * and there is nowhere to inherit so create everything:
	 */
	if (current_tsk == NULL) {
		clone_flags &= ~(CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | CLONE_PARENT);
		current_tsk = &init_lego_task;
	}

	ret = copy_sighand(clone_flags, new, current_tsk);
	if (ret)
		goto bad;
	ret = copy_signal(clone_flags, new, current_tsk);
	if (ret)
		goto bad_cleanup_sighand;
	ret = copy_lego_mm(clone_flags, new, current_tsk);
	if (ret)
		goto bad_cleanup_signal;

	/*
	 * Setup relationship
	 */

	if (clone_flags & CLONE_THREAD) {
		new->exit_signal = -1;
		new->group_leader = current_tsk->group_leader;
		new->tgid = current_tsk->tgid;
	} else {
		if (clone_flags & CLONE_PARENT)
			new->exit_signal = current_tsk->group_leader->exit_signal;
		else
			new->exit_signal = (clone_flags & CSIGNAL);
		new->group_leader = new;
		new->tgid = new->pid;
	}

	/* CLONE_PARENT re-uses the old parent */
	if (clone_flags & (CLONE_PARENT|CLONE_THREAD))
		new->real_parent = current_tsk->real_parent;
	else
		/*
		 * We really don't have a cloner in this case,
		 * just use a special predefined task to indicate
		 * this:
		 */
		new->real_parent = current_tsk ? : &init_lego_task;

	if (thread_group_leader(new)) {
		list_add_tail(&new->sibling, &new->real_parent->children);
	} else {
		list_add_tail(&new->thread_group,
			      &new->group_leader->thread_group);
	}

	return 0;

bad_cleanup_signal:
bad_cleanup_sighand:
bad:
	return ret;
}

static void deinit_lego_task(struct lego_task_struct *tsk)
{

}

int handle_p2m_fork(struct p2m_fork_struct *payload, u64 desc,
		    struct common_header *hdr)
{
	u32 retbuf;
	unsigned int nid = hdr->src_nid;
	unsigned int pid = payload->pid;
	unsigned int current_pid = payload->current_pid;
	unsigned int clone_flags = payload->clone_flags;
	struct lego_task_struct *tsk, *current_tsk;
	int ret;

	pr_info("%s: src_nid:%u pid:%u, current_pid:%u comm:%s\n",
		__func__, nid, pid, current_pid, payload->comm);

	tsk = kmalloc(sizeof(*tsk), GFP_KERNEL);
	if (unlikely(!tsk)) {
		retbuf = RET_ENOMEM;
		goto reply;
	}
	tsk->pid = pid;
	tsk->node = nid;

	/*
	 * current_tsk can be NULL, if this is first fork() request
	 * came from a kernel thread of processor manager.
	 *
	 * Just keep that in mind..
	 */
	current_tsk = find_lego_task_by_pid(nid, current_pid);

	ret = alloc_lego_task(tsk, current_tsk, clone_flags);
	if (unlikely(ret)) {
		retbuf = ERR_TO_LEGO_RET(ret);
		goto reply;
	}

	lego_set_task_comm(tsk, payload->comm);

	ret = ht_insert_lego_task(tsk);
	if (unlikely(ret)) {
		deinit_lego_task(tsk);
		retbuf = ERR_TO_LEGO_RET(ret);
		goto reply;
	}

	retbuf = RET_OKAY;
reply:
	ibapi_reply_message(&retbuf, 4, desc);

	return 0;
}
