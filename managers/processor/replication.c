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

/*
 * At the time of calling, the associated task/mm may have been freed already.
 * Caller needs to provide all necessary information to perform the replication.
 */
void replicate(pid_t tgid, unsigned long user_va,
	       unsigned int m_nid, unsigned int rep_nid, void *cache_addr)
{
	struct p2m_replica_msg *msg;
	struct replica_log *log;
	struct replica_log_meta *meta;
	int ret_len, reply;

	msg = kmalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return;

	fill_common_header(msg, P2M_PCACHE_REPLICA);

	log = &msg->log;
	meta = &log->meta;
	meta->pid = tgid;
	meta->vnode_id = get_vnode_id(tsk);
	meta->nid_processor = LEGO_LOCAL_NID;
	meta->user_va = user_va & PCACHE_LINE_MASK;
	meta->flags = 0;
	meta->csum = 0;
	meta->nid_memory = m_nid;
	memcpy(log->data, cache_addr, PCACHE_LINE_SIZE);

	ibapi_send_reply_timeout(rep_nid, msg, sizeof(*msg),
				 &reply, sizeof(reply), false, DEF_NET_TIMEOUT);

	kfree(msg);
}
