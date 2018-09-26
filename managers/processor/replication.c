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

static DEFINE_PER_CPU(struct p2m_replica_msg, p2m_replica_msg_array);

static inline int post_choose_rep(unsigned int m_nid, unsigned int rep_nid)
{
	return rep_nid;
}

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

	msg = this_cpu_ptr(&p2m_replica_msg_array);

	fill_common_header(msg, P2M_PCACHE_REPLICA);

	log = &msg->log;
	meta = &log->meta;
	meta->pid = tgid;
	meta->vnode_id = 0;
	meta->nid_processor = LEGO_LOCAL_NID;
	meta->user_va = user_va & PCACHE_LINE_MASK;
	meta->flags = 0;
	meta->csum = 0;
	meta->nid_memory = m_nid;
	memcpy(log->data, cache_addr, PCACHE_LINE_SIZE);

	rep_nid = post_choose_rep(m_nid, rep_nid);

	ibapi_send(rep_nid, msg, sizeof(*msg));
}
