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
#include "stat.h"

#define MAX_RXBUF_SIZE	(512 * PAGE_SIZE)

struct info_struct {
	uintptr_t desc;
	char msg[MAX_RXBUF_SIZE];
};

static void handle_bad_request(u32 opcode, uintptr_t desc)
{
	int retbuf;

	pr_info("WARNING: Invalid opcode: %u\n", opcode);

	retbuf = -EINVAL;
	ibapi_reply_message(&retbuf, sizeof(retbuf), desc);
}

#ifdef STORAGE_BYPASS_PAGE_CACHE
static char __user *ubuf;
#endif

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
/* replica log batch flush from Secondary Memory */
	case M2S_REPLICA_FLUSH:
		inc_storage_stat(HANDLE_REPLICA_FLUSH);
		handle_replica_flush(msg, desc);
		break;

/* replica VMA info from Primary Memory*/
	case M2S_REPLICA_VMA:
		inc_storage_stat(HANDLE_REPLICA_VMA);
		handle_replica_vma(msg, desc);
		break;

	case M2S_READ:
		inc_storage_stat(HANDLE_REPLICA_READ);
		handle_read_request(payload, desc);
		break;
	case M2S_WRITE:
		inc_storage_stat(HANDLE_REPLICA_WRITE);
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
	case M2S_LSEEK:
		handle_lseek_request(payload, desc);
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
	case P2S_RENAME:
		handle_rename_request(payload, desc);
		break;

	default:
		handle_bad_request(*opcode, desc);
	}
	return;
}

#if 1
static bool in_handler;

static inline void set_in_handler(void)
{
	in_handler = true;
}

static inline void clear_in_handler(void)
{
	in_handler = false;
}

static int storage_self_monitor(void *unused)
{
	long interval_sec;

	interval_sec = 30;
	while (1) {
		pr_info("%s(): in_handler=%d\n", __func__, in_handler);
		print_storage_manager_stats();

		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(interval_sec * HZ);
	}
	return 0;
}

static int init_self_monitor(void)
{
	struct task_struct *tsk;

	tsk = kthread_run(storage_self_monitor, NULL, "lego-self-monitor");
	if (IS_ERR(tsk)) {
		pr_err("ERROR: Fail to create self monitoring daemon");
		return PTR_ERR(tsk);
	}
	return 0;
}
#else
static inline void set_in_handler(void)
{
}
static inline void clear_in_handler(void)
{
}
static inline int init_self_monitor(void)
{
	return 0;
}
#endif

static int storage_manager(void *unused)
{
	int retlen, reply;
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
			reply = -EFAULT;
			ibapi_reply_message(&reply, sizeof(reply), desc);
		}

		set_in_handler();
		storage_dispatch(msg, desc);
		clear_in_handler();
	}
	return 0;
}

extern int fit_state;

/*
 * If STORAGE_BYPASS_PAGE_CACHE is enabled, we need to have the user
 * context to do mmap. That means we have use the current insmod thread
 * to do so. That further means the insmod thread will never return...
 *
 * For non-storage-intensive workload, you can disable this.
 */
static int __init init_storage_server(void)
{
	int ret = 0;
	struct task_struct *tsk __maybe_unused;
	unsigned long populate __maybe_unused;

	if (fit_state != FIT_MODULE_UP) {
		pr_err("LegoOS FIT module is not ready.");
		return -EIO;
	}

#ifndef STORAGE_BYPASS_PAGE_CACHE
	tsk = kthread_run(storage_manager, NULL, "lego-storaged");
	if (IS_ERR(tsk)) {
		pr_err("ERROR: Fail to create lego_storaged\n");
		return PTR_ERR(tsk);
	}
#else
	ubuf = (char __user *)do_mmap_pgoff(NULL, 0, MAX_RXBUF_SIZE,
			PROT_READ | PROT_WRITE, MAP_SHARED, 0, &populate);
	storage_manager(NULL);
#endif

	ret = init_self_monitor();
	return ret;
}

static void __exit stop_storage_server(void)
{
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
