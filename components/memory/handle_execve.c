/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "handle_p2m_exec(): " fmt

#include <lego/slab.h>
#include <lego/binfmts.h>
#include <lego/kernel.h>
#include <lego/string.h>
#include <lego/fit_ibapi.h>
#include <lego/comp_common.h>
#include <lego/comp_memory.h>

int loader(struct lego_task_struct *tsk, const char *filename,
		u32 argc, const char **argv,
		u32 envc, const char **envp,
		u64 *new_ip, u64 *new_sp)
{
	return 0;
}

int handle_p2m_execve(struct p2m_execve_struct *payload, u64 desc)
{
	struct m2p_execve_struct reply;
	__u32 argc, envc;
	const char **argv, **envp;
	const char *filename, *str;
	__u32 pid;
	struct lego_task_struct *tsk;
	int i;
	__u64 new_ip, new_sp;

	pid = payload->pid;
	argc = payload->argc;
	envc = payload->envc;
	filename = payload->filename;

	pr_info("pid:%u,argc:%u,envc:%u,file:%s\n",
		pid, argc, envc, filename);

	argv = kmalloc(sizeof(*argv) * (argc + envc), GFP_KERNEL);
	if (!argv) {
		reply.status = RET_ENOMEM;
		goto out;
	}

	str = (const char *)&(payload->array);
	for (i = 0; i < (argc + envc); i++) {
		argv[i] = str;
		str += strnlen(str, MAX_ARG_STRLEN);
		/* terminating NULL */
		str++;
	}

	envp = &argv[argc];

	loader(tsk, filename, argc, argv, envc, envp, &new_ip, &new_sp);

	/* XXX: fake one */
	reply.status = RET_OKAY;
	reply.new_ip = 0xA0001000;
	reply.new_sp = 0xC0002000;

	kfree(argv);
out:
	ibapi_reply_message(&reply, sizeof(reply), desc);
	return 0;
}
