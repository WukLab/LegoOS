/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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
#include <processor/processor.h>
#include <monitor/gpm_handler.h>

#define MAX_INIT_ARGS	CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS	CONFIG_INIT_ENV_ARG_LIMIT

static const char *argv[MAX_INIT_ARGS+2];
const char *envp[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };

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
		pr_info("command size larger than buffer sizes\n");
		return -1;
	}
	
	/* skip preceeding space */
	p = skip_spaces(cmd);
	
	/* prasing arguments */
	i = 0;
	while ((arg = strsep(&p, " ")) != NULL)
		argv[i++] = arg;
	
	return 0;
}

static void handle_start_proc(struct pm2p_start_proc_struct *payload, 
				u64 desc, struct common_header *hdr)
{
	/* TODO: vnode need to modify here */
	//int nid = hdr->src_nid; 
	//int vpid = payload->vpid;
	int homenode = payload->homenode;
	int retbuf = RET_OKAY;
	char *msg = (char *)(payload + sizeof(*payload));

	if (parse_cmd(msg, start_proc_msg_size(hdr)) < 0) {
		pr_info("user command cannot start\n");
		retbuf = -EINVAL;
	}

	kernel_thread(program_entry, (void*)&homenode, CLONE_GLOBAL_THREAD); 
	pr_info("new user program starts\n");
	ibapi_reply_message(&retbuf, sizeof(retbuf), desc);
}

static void handle_bad_request(struct common_header *hdr, u64 desc)
{
	int retbuf = -EPERM;

	pr_warn("Unknown: opcode: %u, from node: %u\n",
		hdr->opcode, hdr->src_nid);

	ibapi_reply_message(&retbuf, sizeof(retbuf), desc);
}

static int gm_dispatcher(void* msg, __u64 desc)
{
	struct common_header *hdr;
	void *payload;

	hdr = to_common_header(msg);
	payload = to_payload(msg);
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
	default:
		handle_bad_request(hdr, desc);
	}

	return 0;
}

int gpm_handler(void *unused)
{
	char* msg;
	int port = 0;
	int retlen;
	uintptr_t desc;

	msg = kmalloc(MAX_RXBUF_SIZE, GFP_KERNEL);
	if (unlikely(!msg)) {
		WARN_ON(1);
		do_exit(-1);
	}
	pr_info("GPM handler is up and running\n");

	while (1) {
		/*
		 * This function is blocking,
		 * will return until FIT gets a messages:
		 */
		memset(msg, 0, MAX_RXBUF_SIZE);
		retlen = ibapi_receive_message(port,
				&msg, MAX_RXBUF_SIZE,
				&desc);

		if (unlikely(retlen >= MAX_RXBUF_SIZE))
			panic("retlen: %d,maxlen: %lu", retlen, MAX_RXBUF_SIZE);

		gm_dispatcher(msg, desc);
	}
	return 0;
}

void report_proc_exit(int ret_val)
{
	struct p2pm_exit_proc_struct exit;
	int reply = 0, ret = 0;

	/* TODO: need vpid */
	exit.vpid = 0;
	exit.ret = ret_val;
	ret = net_send_reply_timeout(CONFIG_GPM_NODEID, P2PM_EXIT_PROC, 
				&exit, sizeof(struct p2pm_exit_proc_struct), 
				&reply, sizeof(int), false, FIT_MAX_TIMEOUT_SEC);
	pr_info("done reporting program exit, IB status: %d, reply: %d\n", ret, reply);
}
