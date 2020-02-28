/*
 * Copyright (c) 2016-2020 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "PCOMP_MSG_HANDLER: " fmt

#include <lego/slab.h>
#include <lego/string.h>
#include <lego/fit_ibapi.h>
#include <lego/kthread.h>
#include <processor/processor.h>
#include <processor/vnode.h>
#include <monitor/common.h>

#define MAX_INIT_ARGS	CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS	CONFIG_INIT_ENV_ARG_LIMIT

#define MAX_RXBUF_SIZE	(20 * PAGE_SIZE)

const int ECHO_LEN = 5;
const char* ECHO = "Echo\n";

struct info_struct {
	uintptr_t desc;
	char msg[MAX_RXBUF_SIZE];
};

// TODO: we should consolidate the handlers
static void handle_echo(struct common_header *hdr, u64 desc)
{
	pr_info("Receiving echo: %u, from node: %u\n",
		hdr->opcode, hdr->src_nid);

	ibapi_reply_message(ECHO, ECHO_LEN, desc);
}

static int msg_dispatcher(struct info_struct *info)
{
	uintptr_t desc = info->desc;
	void *payload;
	struct common_header *hdr;

	hdr = to_common_header(info->msg);
	payload = to_payload(info->msg);

	pr_info("~~~~~~~~~~Within Msg Handler~~~~~~~~~~~~~\n");

	/*
	 * BIG FAT NOTE:
	 * 1) Handler MUST call reply message
	 * 2) Handler CAN NOT free payload and hdr
	 * 3) Handler SHOULD NOT call exit()
	 */
	switch (hdr->opcode) {
		default:
			pr_info("~~~~~~~~~~About to handle echo~~~~~~~~~~~~~\n");
			handle_echo(hdr, desc);
	}

	return 0;
}

static int msg_handler(void *unused)
{
	struct info_struct *info;
	int port = 0;
	int retlen;

	info = kmalloc(sizeof(struct info_struct), GFP_KERNEL);
	if (unlikely(!info)) {
		WARN_ON(1);
		do_exit(-1);
	}
	pr_info("~~~~MSG handler is up and running~~~~~~~\n");

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

		uintptr_t desc;
		void *payload;
		struct common_header *hdr;

		desc = info->desc;
		hdr = to_common_header(info->msg);
		payload = to_payload(info->msg);


		if (hdr->src_nid == 0 || hdr->src_nid == 1) {
			pr_info("Reading source nid from header\n", hdr->src_nid);
		}

		msg_dispatcher(info);
	}
	return 0;
}

void msg_handler_init(void)
{
#ifdef CONFIG_COMP_PROCESSOR
	struct task_struct *ret __maybe_unused;

	ret = kthread_run(msg_handler, NULL, "msg_handler");
	if (IS_ERR(ret)) {
		panic("Fail to create msg handler thread");
	}
	pr_info("processor msg handler is up\n");
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
