/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "handle_p2m_exec(): " fmt

#include <lego/kernel.h>
#include <lego/fit_ibapi.h>
#include <lego/comp_common.h>
#include <lego/comp_memory.h>

int handle_p2m_exec(struct p2m_execve_struct *payload, u64 desc)
{
	struct m2p_execve_struct reply;
	__u32 argc, envc;
	const char **argv, **envp, **tmp;
	const char *filename;
	__u32 pid;
	struct lego_task_struct *tsk;
	int i;

	pid = payload->pid;
	argc = payload->argc;
	envc = payload->envc;
	filename = payload->filename;

	pr_info("pid:%u,argc:%u,envc:%u,file:%s\n",
		pid, argc, envc, filename);

	tmp = (const char **)&(payload->array);
	for (i = 0; i < argc+envc; i++) {
		const char *str;

		str = tmp[i];
		pr_info("[%s]\n", str);
	}

	/* XXX: fake one */
	reply.status = RET_OKAY;
	reply.new_ip = 0xA0001000;
	reply.new_sp = 0xC0002000;

	ibapi_reply_message(&reply, sizeof(reply), desc);
	return 0;
}
