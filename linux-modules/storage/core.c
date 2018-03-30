/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/param.h>
#include <linux/kthread.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/mutex.h>
#include <linux/mm.h>

#include "../fit/fit_config.h"
#include "storage.h"
#include "common.h"

#define MAX_RXBUF_SIZE	(129 * PAGE_SIZE)

struct info_struct {
	uintptr_t desc;
	char msg[MAX_RXBUF_SIZE];
};

static void handle_bad_request(u32 opcode, uintptr_t desc)
{
	int retbuf;

	pr_debug("WARNING: Invalid opcode: %u\n", opcode);

	retbuf = EFAULT;
	ibapi_reply_message(&retbuf, sizeof(retbuf), desc);
}

static void storage_dispatch(void *msg, uintptr_t desc)
{
	u32 *opcode;
	void *payload;

	opcode = msg;
	payload = msg + sizeof(*opcode);

#ifdef STORAGE_DEBUG_CORE
	pr_info("storage_dispatch : check pointer address : \n");
	pr_info("msg %lu\n", msg);
#endif

	switch (*opcode) {
	case M2S_READ:
		handle_read_request(payload, desc);
		break;
	case M2S_WRITE:
		handle_write_request(payload, desc);
		break;
	case P2S_OPEN:
		handle_open_request(payload, desc);
		break;
	case P2S_ACCESS:
		handle_access_request(payload, desc);
		break;
	case P2S_STAT:
		handle_stat_request(payload, desc);
		break;
	case P2S_TRUNCATE:
		handle_truncate_request(payload, desc);
		break;
	case P2S_UNLINK:
		handle_unlink_request(payload, desc);
		break;
	case P2S_MKDIR:
		handle_mkdir_request(payload, desc);
		break;
	case P2S_RMDIR:
		handle_rmdir_request(payload, desc);
		break;
	case P2S_STATFS:
		handle_statfs_request(payload, desc);
		break;
	case P2S_GETDENTS:
		handle_getdents_request(payload, desc);
		break;
	case P2S_READLINK:
		handle_readlink_request(payload, desc);
		break;

	default:
		handle_bad_request(*opcode, desc);
	}
	return;
}

static int storage_manager(void *unused)
{
	int retlen;
	void *msg;
	uintptr_t desc;

	msg = kmalloc(MAX_RXBUF_SIZE, GFP_KERNEL);
	if (!msg) {
		WARN_ON(1);
		return -ENOMEM;
	}

	while(1) {
		retlen = ibapi_receive_message(0, msg, MAX_RXBUF_SIZE, &desc);
		if (unlikely(retlen >= MAX_RXBUF_SIZE)) {
			WARN(1, "retlen=%d MAX_RETBUF_SIZE=%lu", retlen, MAX_RXBUF_SIZE);
			break;
		}

		storage_dispatch(msg, desc);
	}
	return 0;	
}

static int __init init_storage_server(void)
{
	struct task_struct *tsk;

	tsk = kthread_run(storage_manager, NULL, "lego_storaged");
	if (IS_ERR(tsk)){
		pr_err("ERROR: Fail to create lego_storaged\n");
		return PTR_ERR(tsk);
	}

	return 0;
}

static void __exit stop_storage_server(void) {
	/*
	 * TODO: DO NOT JUST EXIT
	 * Cleanup things such as allocated memory,
	 * opened file, created thread.
	 */
	printk(KERN_INFO "Bye, storage server!\n");
}

module_init(init_storage_server);
module_exit(stop_storage_server);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("yilun");
