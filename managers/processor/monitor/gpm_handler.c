/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "GPM_HANDLER: " fmt

#include <lego/slab.h>
#include <lego/string.h>
#include <lego/fit_ibapi.h>
#include <lego/kthread.h>
#include <processor/processor.h>
#include <processor/vnode.h>
#include <monitor/common.h>
#include <monitor/gpm_handler.h>

#define MAX_INIT_ARGS	CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS	CONFIG_INIT_ENV_ARG_LIMIT

static const char *argv[MAX_INIT_ARGS+2];
const char *envp[MAX_INIT_ENVS+2] =
{
	"HOME=/",
	"TERM=linux",
	"LANG=en_US.UTF-8",
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin",
	"USER=root",
	"PWD=/",
	NULL,
};

struct info_struct {
	uintptr_t desc;
	char msg[MAX_RXBUF_SIZE];
};

static int program_entry(void *arg)
{
	const char *file;
	int *homenode = (int *)arg;
	file = argv[0];
	set_memory_home_node(current, *homenode);
	return do_execve(file,	(const char *const *)argv,
				(const char *const *)envp);
}

static int parse_cmd(char* cmd, int buf_len)
{
	char *p, *arg;
	int len, i = 0;

	pr_info("cmd passed: %s\n", cmd);
	len = strlen(cmd);
	if (unlikely(len >= buf_len)) {
		pr_info("command length exceed maximum buffer size\n");
		return -EINVAL;
	}
	
	/* skip preceeding space */
	p = skip_spaces(cmd);
	
	/* prasing arguments */
	i = 0;
	while ((arg = strsep(&p, " ")) != NULL)
		argv[i++] = arg;
	
	return 0;
}

static char *to_cmd(struct pm2p_start_proc_struct *payload)
{
	return (char *)((void *)payload + sizeof(struct pm2p_start_proc_struct));
}

static void handle_start_proc(struct pm2p_start_proc_struct *payload, 
				u64 desc, struct common_header *hdr)
{
	/* TODO: vnode need to modify here */
	//int nid = hdr->src_nid; 
	//int vpid = payload->vpid;
	int retbuf = 0;
	int homenode = payload->homenode;
	char *cmd = to_cmd(payload);

	retbuf = parse_cmd(cmd, max_cmd_len);
	if (retbuf) {
		pr_info("user command cannot start\n");
		ibapi_reply_message(&retbuf, sizeof(retbuf), desc);
		return;
	}

	kernel_thread(program_entry, (void*)&homenode, CLONE_GLOBAL_THREAD); 
	ibapi_reply_message(&retbuf, sizeof(retbuf), desc);
	pr_info("new user program starts\n");
}

static void handle_bad_request(struct common_header *hdr, u64 desc)
{
	int retbuf = -EPERM;

	pr_warn("Unknown: opcode: %u, from node: %u\n",
		hdr->opcode, hdr->src_nid);

	ibapi_reply_message(&retbuf, sizeof(retbuf), desc);
}

static int gm_dispatcher(struct info_struct *info)
{
	uintptr_t desc = info->desc;
	void *payload;
	struct common_header *hdr;

	hdr = to_common_header(info->msg);
	payload = to_payload(info->msg);

	/*
	 * BIG FAT NOTE:
	 * 1) Handler MUST call reply message
	 * 2) Handler CAN NOT free payload and hdr
	 * 3) Handler SHOULD NOT call exit()
	 */
	switch (hdr->opcode) {
	case PM2P_START_PROC:
		handle_start_proc(payload, desc, hdr);
		break;

#ifdef CONFIG_VNODE
	case PM2P_BROADCAST_VNODE:
		handle_pm2p_broadcast_vnode((void *)info->msg, desc);
		break;
#endif

	default:
		handle_bad_request(hdr, desc);
	}

	return 0;
}

static int gpm_handler(void *unused)
{
	struct info_struct *info;
	int port = 0;
	int retlen;

	info = kmalloc(sizeof(struct info_struct), GFP_KERNEL);
	if (unlikely(!info)) {
		WARN_ON(1);
		do_exit(-1);
	}
	pr_info("GPM handler is up and running\n");

	while (1) {
		/*
		 * This function is blocking,
		 * will return until FIT gets a messages:
		 */
		memset(info, 0, sizeof(struct info_struct));
		retlen = ibapi_receive_message(port,
				info->msg, MAX_RXBUF_SIZE,
				&info->desc);

		if (unlikely(retlen >= MAX_RXBUF_SIZE))
			panic("retlen: %d,maxlen: %lu", retlen, MAX_RXBUF_SIZE);

		gm_dispatcher(info);
	}
	return 0;
}

void gpm_handler_init(void)
{
#ifdef CONFIG_GPM
	struct task_struct *ret __maybe_unused;

	ret = kthread_run(gpm_handler, NULL, "gpm_handler");
	if (IS_ERR(ret))
		panic("Fail to create gpm handler thread");
	pr_info("processor monitor handler is up\n");
#endif
}

void report_proc_exit(int ret_val)
{
#ifdef CONFIG_GPM
	struct p2pm_exit_proc_struct exit;
	int reply = 0, ret = 0;

	/* TODO: need vpid */
	exit.vpid = 0;
	exit.ret = ret_val;
	ret = net_send_reply_timeout(CONFIG_GPM_NODEID, P2PM_EXIT_PROC, 
				&exit, sizeof(struct p2pm_exit_proc_struct), 
				&reply, sizeof(int), false, FIT_MAX_TIMEOUT_SEC);
	pr_info("done reporting program exit, IB status: %d, reply: %d\n", ret, reply);
#endif
}
