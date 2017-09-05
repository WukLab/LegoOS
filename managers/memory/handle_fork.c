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
	return 0;
}

static int dup_lego_mm(struct lego_task_struct *t,
		       struct lego_task_struct *parent)
{
	struct lego_mm_struct *mm, *oldmm;
	int err;

	mm = lego_mm_alloc(t);
	if (!mm)
		return -ENOMEM;

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
	unsigned int pid = payload->pid;
	unsigned int tgid = payload->tgid;
	unsigned int parent_tgid = payload->parent_tgid;
	struct lego_task_struct *tsk, *parent;
	u32 retbuf;
	int ret;

	pr_info("%s(): nid:%u,pid:%u,tgid:%u,parent_tgid:%u\n",
		__func__, nid, pid, tgid, parent_tgid);

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
	ibapi_reply_message(&retbuf, 4, desc);

	return 0;
}
