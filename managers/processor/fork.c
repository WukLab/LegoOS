/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <processor/processor.h>

#ifdef CONFIG_DEBUG_FORK
#define fork_debug(fmt, ...)						\
	pr_debug("%s(cpu%d): " fmt "\n", __func__, smp_processor_id(),	\
		__VA_ARGS__)
#else
static inline void fork_debug(const char *fmt, ...) { }
#endif

/*
 * Return 0 on success, -ENOMEM on failure.
 * fork() syscall does not have too many errno options.
 */
int p2m_fork(struct task_struct *p, unsigned long clone_flags)
{
	struct p2m_fork_struct payload;
	int retlen, reply;
	int retval = -ENOMEM;

	BUG_ON(!p);

	fork_debug("I cur:%d-%s new:%d", current->pid, current->comm, p->pid);

	payload.pid = p->pid;
	payload.tgid = p->tgid;
	payload.parent_tgid = p->real_parent->tgid;
	payload.clone_flags = clone_flags;
	memcpy(payload.comm, p->comm, TASK_COMM_LEN);

	retlen = net_send_reply_timeout(p->home_node, P2M_FORK, &payload,
				sizeof(payload), &reply, sizeof(reply), false,
				DEF_NET_TIMEOUT);

	if (retlen < sizeof(reply)) {
		pr_warn("%s():. net %d:%s cur:%d-%s new:%d\n",
			FUNC, retlen, perror(retlen),
			current->pid, current->comm, p->pid);
		goto out;
	}

	if (unlikely(reply != 0)) {
		pr_warn("%s(): reply %d:%s. cur:%d-%s new:%d\n",
			FUNC, reply, perror(reply),
			current->pid, current->comm, p->pid);
		goto out;
	}

	fork_debug("O succeed cur:%d-%s new:%d", current->pid, current->comm, p->pid);
	retval = 0;
out:
	return retval;
}
