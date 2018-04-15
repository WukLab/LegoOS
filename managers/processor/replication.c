/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/wait.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/hash.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/profile.h>
#include <lego/syscalls.h>
#include <lego/jiffies.h>
#include <lego/fit_ibapi.h>
#include <processor/pcache.h>
#include <processor/processor.h>
#include <processor/distvm.h>

void replicate(struct task_struct *tsk, unsigned long user_va, void *cache_addr)
{
	struct p2m_replica_msg *msg;
	struct replica_log *log;
	struct replica_log_meta *meta;
	int ret_len, reply;
	int replica_mnode_id;

	msg = kmalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return;

	fill_common_header(msg, P2M_PCACHE_REPLICA);

	log = &msg->log;
	meta = &log->meta;
	meta->pid = tsk->tgid;
	meta->vnode_id = get_vnode_id(tsk);
	meta->nid_processor = LEGO_LOCAL_NID;
	meta->user_va = user_va & PCACHE_LINE_MASK;
	meta->flags = 0;
	meta->csum = 0;

	/*
	 * The memory node where we are sending clflush to
	 *
	 * XXX: Caution! This might got changed after clflush!
	 */
	meta->nid_memory = get_memory_node(tsk, user_va);
	memcpy(log->data, cache_addr, PCACHE_LINE_SIZE);

	replica_mnode_id = get_replica_node_by_addr(tsk, user_va);

	ret_len = ibapi_send_reply_timeout(replica_mnode_id, msg, sizeof(*msg),
					   &reply, sizeof(reply), false, DEF_NET_TIMEOUT);
	if (ret_len != sizeof(reply))
		goto free;

	if (unlikely(reply))
		pr_err("%s(): %s tsk: %d user_va: %#lx\n",
			FUNC, perror(reply), tsk->pid, user_va);

free:
	kfree(msg);
}
