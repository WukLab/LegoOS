/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "handle_execve: " fmt

#include <lego/slab.h>
#include <lego/kernel.h>
#include <lego/string.h>
#include <lego/fit_ibapi.h>
#include <lego/comp_common.h>
#include <lego/comp_memory.h>

#include "include/loader.h"

int handle_p2m_execve(struct p2m_execve_struct *payload, u64 desc,
		      struct common_header *hdr)
{
	struct m2p_execve_struct reply;
	__u32 argc, envc;
	const char **argv, **envp;
	const char *filename, *str;
	__u32 pid;
	struct lego_task_struct *tsk;
	int i, ret;
	__u64 new_ip, new_sp;

	pid = payload->pid;
	argc = payload->argc;
	envc = payload->envc;
	filename = payload->filename;

	pr_info("pid:%u,argc:%u,envc:%u,file:%s\n",
		pid, argc, envc, filename);

	argv = kzalloc(sizeof(*argv) * (argc + envc), GFP_KERNEL);
	if (!argv) {
		reply.status = RET_ENOMEM;
		goto out_reply;
	}

	/* Prepare argv and envp */
	str = (const char *)&(payload->array);
	for (i = 0; i < (argc + envc); i++) {
		argv[i] = str;
		str += strnlen(str, MAX_ARG_STRLEN);
		/* terminating NULL */
		str++;
	}
	envp = &argv[argc];

	/* Invoke real loader */
	ret = exec_loader(tsk, filename, argc, argv, envc, envp,
			  &new_ip, &new_sp);
	if (ret) {
		reply.status = RET_EPERM;
		goto out;
	}

	reply.status = RET_OKAY;
	reply.new_ip = new_ip;
	reply.new_sp = new_sp;

out:
	kfree(argv);
out_reply:
	ibapi_reply_message(&reply, sizeof(reply), desc);
	return 0;
}
