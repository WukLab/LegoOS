/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file describes routines for handling
 * 	pcache line flush
 */

#include <lego/fit_ibapi.h>
#include <lego/ratelimit.h>
#include <lego/comp_memory.h>
#include <lego/comp_storage.h>
#include <lego/checksum.h>
#include <memory/vm.h>
#include <memory/pid.h>
#include <processor/pcache.h>

#include "internal.h"

#ifdef CONFIG_DEBUG_HANDLE_PCACHE_FLUSH
#define clflush_debug(fmt, ...)					\
	pr_debug("%s() cpu%2d " fmt "\n",			\
		__func__, smp_processor_id(), __VA_ARGS__);
#else
static inline void clflush_debug(const char *fmt, ...) { }
#endif

void verify_checksum(struct lego_task_struct *tsk, void *user_va)
{
	void *buf;
	__wsum csum;

	buf = kmalloc(PCACHE_LINE_SIZE, GFP_KERNEL);
	if (!buf)
		return;

	if (!lego_copy_from_user(tsk, buf, user_va, PCACHE_LINE_SIZE))
		return;

	csum = csum_partial(buf, PCACHE_LINE_SIZE, 0);
	clflush_debug("  csum of updated vm page: (%#x)", csum);

	kfree(buf);
}

int handle_p2m_flush_one(struct p2m_flush_msg *msg, u64 desc)
{
	int reply;
	unsigned int src_nid;
	pid_t pid;
	void *user_va;
	struct lego_task_struct *tsk;

	src_nid = to_common_header(msg)->src_nid;
	pid = msg->pid;
	user_va = (void *)msg->user_va;

	clflush_debug("I nid:%u tgid:%u user_va:%p", src_nid, pid, user_va);

	if (offset_in_page(user_va)) {
		reply = -EINVAL;
		WARN_ON_ONCE(1);
		goto out_reply;
	}

	tsk = find_lego_task_by_pid(src_nid, pid);
	if (!tsk) {
		reply = -ESRCH;
		goto out_reply;
	}

	if (!lego_copy_to_user(tsk, user_va, msg->pcacheline,
				PCACHE_LINE_SIZE)) {
		reply = -EFAULT;
		goto out_reply;
	}

	reply = 0;

out_reply:
	clflush_debug("O nid:%u tgid:%u user_va:%p reply: %d %s",
		src_nid, pid, user_va, reply, perror(reply));

	ibapi_reply_message(&reply, sizeof(reply), desc);
	return 0;
}
