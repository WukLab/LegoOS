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

int handle_p2m_fork(struct p2m_fork_struct *payload, u64 desc,
		    struct common_header *hdr)
{
	u32 retbuf;
	unsigned int nid = hdr->src_nid;
	unsigned int pid = payload->pid;
	unsigned int tgid = payload->tgid;
	unsigned int clone_flags = payload->clone_flags;
	struct lego_task_struct *tsk;
	int ret;

	pr_info("%s(): nid:%u,pid:%u,tgid:%u\n",
		__func__, nid, pid, tgid);

	tsk = kmalloc(sizeof(*tsk), GFP_KERNEL);
	if (unlikely(!tsk)) {
		retbuf = RET_ENOMEM;
		goto reply;
	}

	/* All threads within process share one VM */
	tsk->pid = tgid;
	tsk->node = nid;

	lego_set_task_comm(tsk, payload->comm);

	ret = ht_insert_lego_task(tsk);
	if (unlikely(ret)) {
		/* Same process */
		if (likely(ret == -EEXIST && (clone_flags & CLONE_VM)))
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
