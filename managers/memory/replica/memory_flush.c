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
#include <lego/profile.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/task.h>
#include <memory/replica.h>
#include <processor/pcache.h>

DEFINE_PROFILE_POINT(m2s_replica_flush)

/*
 * This code runs on Secondary Memory,
 * used to flush the batched log to Storage.
 */

void flush_replica_struct(struct replica_struct *r)
{
	size_t msg_size;
	int reply, storage_node;
	struct m2s_replica_flush_msg *msg;
	PROFILE_POINT_TIME(m2s_replica_flush)

	/*
	 * The message is pre-cooked when we create
	 * the in-memory cached log.
	 */
	msg = r->flush_msg;
	msg_size = r->flush_msg_size;
	storage_node = CONFIG_DEFAULT_STORAGE_NODE;;

	PROFILE_START(m2s_replica_flush);
	ibapi_send_reply_timeout(storage_node, msg, msg_size,
				&reply, sizeof(reply), false, DEF_NET_TIMEOUT);
	PROFILE_LEAVE(m2s_replica_flush);
}
