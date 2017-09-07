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

#ifdef CONFIG_DEBUG_HANDLE_FORK
#define fork_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)

#define dump_both_vmas(mm, oldmm)		\
	do {					\
		dump_all_vmas_simple(mm);	\
		dump_all_vmas_simple(oldmm);	\
	} while (0)
#else
#define fork_debug(fmt, ...)		do { } while (0)
#define dump_both_vmas(mm, oldmm)	do { } while (0)
#endif

/*
 * This function duplicate mmap layout from parent,
 * which is the basic COW guarantee of fork().
 *
 * The whole lego_mm_struct will be replcaed by a new one
 * when execve() is called. This is also what execve() guarantees.
 * Check managers/memory/loader/vm.c for detail.
 */
static int dup_lego_mmap(struct lego_mm_struct *mm,
			 struct lego_mm_struct *oldmm)
{
	struct vm_area_struct *mpnt, *tmp, *prev, **pprev;
	struct rb_node **rb_link, *rb_parent;
	int ret = 0;

	if (down_write_killable(&oldmm->mmap_sem))
		return -EINTR;

	down_write(&mm->mmap_sem);

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

		tmp = kmalloc(sizeof(*tmp), GFP_KERNEL);
		if (!tmp) {
			ret = -ENOMEM;
			goto out;
		}

		*tmp = *mpnt;
		INIT_LIST_HEAD(&tmp->anon_vma_chain);
		tmp->vm_mm = mm;

		tmp->vm_flags &=
			~(VM_LOCKED|VM_LOCKONFAULT|VM_UFFD_MISSING|VM_UFFD_WP);
		tmp->vm_next = tmp->vm_prev = NULL;

		/* Hold 1 more ref */
		file = tmp->vm_file;
		if (file)
			get_lego_file(file);

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
		ret = lego_copy_page_range(mm, oldmm, mpnt);

		/*
		 * Callback to underlying fs hook if exists:
		 */
		if (tmp->vm_ops && tmp->vm_ops->open)
			tmp->vm_ops->open(tmp);

		if (ret)
			goto out;
	}

	dump_both_vmas(mm, oldmm);
	ret = 0;
out:
	up_write(&mm->mmap_sem);
	up_write(&oldmm->mmap_sem);
	return ret;
}

static int dup_lego_mm(struct lego_task_struct *t,
		       struct lego_task_struct *parent)
{
	struct lego_mm_struct *mm, *oldmm;
	int err;

	mm = lego_mm_alloc(t, parent);
	if (!mm)
		return -ENOMEM;
	t->mm = mm;

	if (parent) {
		oldmm = parent->mm;
		err = dup_lego_mmap(mm, oldmm);
		if (err)
			goto out;
	} else {
		/*
		 * The only possibility that parent is NULL
		 * is that this is the first process here.
		 * And it will call the execve() immediately.
		 */
	}

	return 0;

out:
	lego_mmput(mm);
	return err;
}

int handle_p2m_fork(struct p2m_fork_struct *payload, u64 desc,
		    struct common_header *hdr)
{
	unsigned int nid = hdr->src_nid;
	unsigned int tgid = payload->tgid;
	unsigned int parent_tgid = payload->parent_tgid;
	struct lego_task_struct *tsk, *parent;
	u32 retbuf;
	int ret;

	fork_debug("nid:%u,pid:%u,tgid:%u,parent_tgid:%u",
		nid, payload->pid, tgid, parent_tgid);

	parent = find_lego_task_by_pid(nid, parent_tgid);
	if (!parent && parent_tgid != 1)
		WARN_ONCE(1, "From processor-daemon?");

	tsk = kmalloc(sizeof(*tsk), GFP_KERNEL);
	if (unlikely(!tsk)) {
		retbuf = RET_ENOMEM;
		goto reply;
	}

	/*
	 * All threads within process share one VM
	 * So we actually use tgid (thread-group-id) to create
	 * a lego-tsk entity.
	 *
	 * All following requests sent from processor must use tgid.
	 */

	tsk->pid = tgid;
	tsk->parent_pid = parent_tgid;
	tsk->node = nid;
	spin_lock_init(&tsk->task_lock);
	lego_set_task_comm(tsk, payload->comm);

	/* Duplicate the mmap from parent */
	ret = dup_lego_mm(tsk, parent);
	if (ret) {
		kfree(tsk);
		retbuf = ERR_TO_LEGO_RET(ret);
		goto reply;
	}

	/* All done, insert into hashtable */
	ret = ht_insert_lego_task(tsk);
	if (unlikely(ret)) {
		lego_mmput(tsk->mm);
		kfree(tsk);

		/* Same process? */
		if (likely(ret == -EEXIST))
			retbuf = RET_OKAY;
		else
			retbuf = ERR_TO_LEGO_RET(ret);
		goto reply;
	}

	retbuf = RET_OKAY;
reply:
	fork_debug("retbuf: %s", ret_to_string(retbuf));
	ibapi_reply_message(&retbuf, 4, desc);
	return 0;
}
