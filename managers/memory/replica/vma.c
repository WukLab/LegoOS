/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/slab.h>
#include <lego/kernel.h>
#include <lego/spinlock.h>
#include <lego/checksum.h>
#include <lego/hashtable.h>
#include <lego/fit_ibapi.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/task.h>
#include <memory/replica.h>
#include <processor/pcache.h>

/*
 * This code runs on Primary Memory,
 * used to replicate VMA info to Storage.
 */

void replicate_vma(struct lego_task_struct *p, int action,
		   unsigned long new_addr, unsigned long new_len,
		   unsigned long old_addr, unsigned long old_len)
{
	struct m2s_replica_vma_msg msg;
	struct replica_vma_log *log;
	int dst_storage, reply;

	msg.opcode = M2S_REPLICA_VMA;
	log = &msg.log;
	log->pid = p->pid;
	log->vnode_id = p->vnode_id;
	log->action = action;
	log->new_addr = new_addr;
	log->new_len = new_len;
	log->old_addr = old_addr;
	log->old_len = old_len;

	dst_storage = CONFIG_DEFAULT_STORAGE_NODE;
	ibapi_send_reply_timeout(dst_storage, &msg, sizeof(msg),
				 &reply, sizeof(reply), false, DEF_NET_TIMEOUT);
}
