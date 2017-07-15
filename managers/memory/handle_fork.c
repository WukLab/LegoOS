/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/fit_ibapi.h>
#include <lego/comp_common.h>
#include <lego/comp_memory.h>

#include <memory/include/vm.h>
#include <memory/include/pid.h>

int handle_p2m_fork(struct p2m_fork_struct *payload, u64 desc,
		    struct common_header *hdr)
{
	u32 retbuf;
	struct lego_task_struct *tsk;
	int ret;

	pr_info("%s: src_nid: %u remote pid: %d, comm: %s\n",
		__func__, hdr->src_nid, payload->pid, payload->comm);

	tsk = alloc_lego_task(hdr->src_nid, payload->pid);
	if (unlikely(IS_ERR_OR_NULL(tsk))) {
		ret = PTR_ERR(tsk);
		retbuf = ERR_TO_LEGO_RET(ret);
		goto reply;
	}

	ret = init_lego_task(tsk);
	if (unlikely(ret)) {
		retbuf = ERR_TO_LEGO_RET(ret);
		goto reply;
	}
	lego_set_task_comm(tsk, payload->comm);

	retbuf = RET_OKAY;
reply:
	ibapi_reply_message(&retbuf, 4, desc);
	return 0;
}
