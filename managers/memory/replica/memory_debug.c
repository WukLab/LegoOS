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

void dump_replica_log(struct replica_log *log, int idx)
{
	struct replica_log_meta *m= &log->meta;

	pr_debug(" [%2d] pid: %2u vnode_id: %2u nid_p: %2u nid_m: %2u "
		 "user_va: %#018lx flags: %#x csum: %x\n",
		idx, m->pid, m->vnode_id, m->nid_processor, m->nid_memory,
		m->user_va, m->flags, m->csum);
}

void dump_replica_struct(struct replica_struct *r, char *reason)
{
	struct replica_log *log;
	int i;

	pr_debug("  replica_struct dumped because %s\n"
		 "     nr_log: %u HEAD: %u pid: %u vnode_id: %u nid_p: %u nid_m: %u\n"
		 "     flush_msg: %p msg_size: %zu log: %p\n",
		 reason ? reason : " ",
		 r->nr_log, r->HEAD, r->pid, r->vnode_id, r->nid_processor, r->nid_memory,
		 r->flush_msg, r->flush_msg_size, r->log);

	spin_lock(&r->lock);
	for (i = 0; i < r->HEAD; i++) {
		log = &r->log[i];
		dump_replica_log(log, i);
	}
	spin_unlock(&r->lock);
	pr_debug("  End --\n");
}

void dump_all_replica(void)
{

}
