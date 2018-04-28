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
#include <lego/string.h>
#include <lego/fit_ibapi.h>
#include <lego/comp_memory.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/loader.h>
#include <memory/distvm.h>
#include <memory/thread_pool.h>

#ifdef CONFIG_DEBUG_HANDLE_EXECVE
#define execve_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)

static void
debug_argv_envp_array(u32 argc, const char **argv, unsigned long *argv_len,
		      u32 envc, const char **envp, unsigned long *envp_len)
{
	int i;

	for (i = 0; i < argc; i++)
		pr_debug("    argc[%u] (len:%3lu):  %s\n",
			i, argv_len[i], argv[i]);

	for (i = 0; i < envc; i++)
		pr_debug("    envc[%u] (len:%3lu):  %s\n",
			i, envp_len[i], envp[i]);
}

#else
static inline void execve_debug(const char *fmt, ...) { }
static inline void
debug_argv_envp_array(u32 argc, const char **argv, unsigned long *argv_len,
		      u32 envc, const char **envp, unsigned long *envp_len)
{ }
#endif

void handle_p2m_execve(struct p2m_execve_struct *payload,
		       struct common_header *hdr, struct thpool_buffer *tb)
{
	__u32 argc, envc;
	size_t len;
	unsigned long *argv_len, *envp_len;
	const char **argv, **envp;
	const char *filename, *str;
	__u32 pid;
	struct lego_task_struct *tsk;
	int i, ret;
	__u64 new_ip, new_sp;
	struct m2p_execve_struct *reply;

	reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	pid = payload->pid;
	argc = payload->argc;
	envc = payload->envc;
	filename = payload->filename;

	execve_debug("pid:%u,argc:%u,envc:%u,file:%s",
		pid, argc, envc, filename);

	tsk = find_lego_task_by_pid(hdr->src_nid, pid);
	if (!tsk) {
		reply->status = RET_ESRCH;
		return;
	}

	argv = kzalloc(sizeof(*argv) * (argc + envc), GFP_KERNEL);
	if (!argv) {
		reply->status = RET_ENOMEM;
		return;
	}

	argv_len = kzalloc(sizeof(*argv_len) * (argc + envc), GFP_KERNEL);
	if (!argv_len) {
		kfree(argv);
		reply->status = RET_ENOMEM;
		return;
	}

	/* Prepare argv and envp */
	str = (const char *)&(payload->array);
	for (i = 0; i < (argc + envc); i++) {
		argv[i] = str;

		len = strnlen(str, MAX_ARG_STRLEN);
		len++;	/* terminating NULL */
		str += len;

		/* this array of length including terminal NULL */
		argv_len[i] = len;
	}
	envp = &argv[argc];
	envp_len = &argv_len[argc];

	debug_argv_envp_array(argc, argv, argv_len, envc, envp, envp_len);

	/*
	 * Callback to real loader
	 * which will assign @new_ip and @new_sp
	 */
	ret = exec_loader(tsk, filename, argc, argv, argv_len,
			  envc, envp, envp_len,
			  &new_ip, &new_sp
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
			  ,&reply->map
#endif
			  );

	if (ret) {
		reply->status = RET_EPERM;
		goto out;
	}

	reply->status = RET_OKAY;
	reply->new_ip = new_ip;
	reply->new_sp = new_sp;

out:
	kfree(argv);
	kfree(argv_len);

	execve_debug("reply_status: %s, new_ip: %#Lx, new_sp: %#Lx",
		ret_to_string(reply->status), reply->new_ip, reply->new_sp);

#ifdef CONFIG_DEBUG_VMA
	dump_reply(&reply->map);
#endif
}
