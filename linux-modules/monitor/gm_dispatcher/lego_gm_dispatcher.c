/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kthread.h>

#include <common.h>
#include <gmm.h>
#include <gpm.h>

/* 
 * this module act as a linux module ib receiver and dispatcher,
 * allowing us to run multiple linux modules using ibapi on same
 * machine to save some debuging time in booting machine
 */

static struct task_struct *listening;
static char rcvbuf[MAX_RXBUF_SIZE];
static unsigned long desc;

static void handle_bad_request(struct common_header *hdr, u64 desc)
{
	u32 retbuf;

	pr_warn("Unknown: opcode: %u, from node: %u\n",
		hdr->opcode, hdr->src_nid);

	retbuf = -EPERM;
	ibapi_reply_message(&retbuf, 4, desc);
}

static int req_dispatcher(void)
{
	struct common_header *hdr;
	void *payload;

	hdr = to_common_header((void *)rcvbuf);
	payload = to_payload((void *)rcvbuf);

	/*
	 * BIG FAT NOTE:
	 * 1) Handler MUST call reply message
	 * 2) Handler CAN NOT free payload and hdr
	 * 3) Handler SHOULD NOT call exit()
	 */
	switch (hdr->opcode) {
	case P2PM_EXIT_PROC:
		handle_p2pm_exit_proc(payload, desc, hdr);
		break;

	case M2MM_CONSULT:
		handle_m2mm_consult(payload, desc, hdr);
		break;

	case P2PM_REQUEST_VNODE:
		handle_p2pm_request_vnode((void *)rcvbuf, desc);
		break;

	case M2MM_STATUS_REPORT:
		handle_m2mm_status_report((void *)rcvbuf, desc);
		break;

	default:
		handle_bad_request(hdr, desc);
	}

	return 0;
}
	
static int fit_polling(void *unused)
{
	int port = 0;
	int retlen;

	while (!kthread_should_stop()) {
		/*
		 * This function is blocking,
		 * will return until FIT gets a messages:
		 */
		memset(rcvbuf, 0, MAX_RXBUF_SIZE);
		retlen = ibapi_receive_message(port, &rcvbuf, MAX_RXBUF_SIZE,
				&desc);

		if (unlikely(retlen >= MAX_RXBUF_SIZE))
			pr_warn("retlen: %d,maxlen: %lu", retlen, MAX_RXBUF_SIZE);

		req_dispatcher();
	}
	return 0;
}

static int __init lego_gm_dispatcher_init(void)
{
	pr_info("lego monitor dispatcher module init called\n");
	listening = kthread_run(fit_polling, NULL, "lego_gm_dispatcher");
	return IS_ERR(listening);
}

static void __exit lego_gm_dispatcher_exit(void)
{
	pr_info("lego monitor dispatcher module exit called\n");
	kthread_stop(listening);
}

module_init(lego_gm_dispatcher_init);
module_exit(lego_gm_dispatcher_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wuklab@Purdue");
