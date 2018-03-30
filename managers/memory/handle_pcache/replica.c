/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/fit_ibapi.h>
#include <lego/ratelimit.h>
#include <lego/checksum.h>
#include <lego/hashtable.h>

#include <memory/mm.h>
#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/replica.h>
#include <processor/pcache.h>

#ifdef CONFIG_DEBUG_HANDLE_REPLICA
# define replica_debug(fmt, ...)	\
	pr_debug("%s() CPU%d " fmt "\n", __func__, smp_processor_id(), __VA_ARGS__)
#else
# define replica_debug(fmt, ...)	do { } while (0)
#endif


void handle_p2m_replica(void *_msg, u64 desc)
{
	struct p2m_replica_msg *msg = _msg;
	int reply = 0;

	printk("%s(): pid: %u user_va: %lx\n", __func__, msg->pid, msg->user_va);

	ibapi_reply_message(&reply, sizeof(reply), desc);
}
