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
 * This code runs on Secondary Memory,
 * used to flush the batched log to Storage.
 */

int flush_replica_struct(struct replica_struct *r)
{
	struct m2s_replica_flush_msg *msg;
	size_t msg_size, log_size;
	int reply, retval, ret_len;
	int storage_node;

	/* opcode + nr_log + ARRAY */
	log_size = r->nr_log * sizeof(struct replica_log);
	msg_size = 8 + log_size;

	msg = kmalloc(msg_size, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	msg->opcode = M2S_REPLICA_FLUSH;
	msg->nr_log = r->nr_log;
	memcpy(&msg->log, r->log, log_size);

	storage_node = 2;
	ret_len = ibapi_send_reply_timeout(storage_node, msg, msg_size,
				&reply, sizeof(reply), false, DEF_NET_TIMEOUT);
	if (ret_len != sizeof(reply)) {
		retval = -EIO;
		goto out;
	}

	if (unlikely(reply)) {
		pr_err("%s() %s\n", __func__, perror(reply));
		retval = reply;
		goto out;
	}

	retval = 0;
out:
	kfree(msg);
	return retval;
}
