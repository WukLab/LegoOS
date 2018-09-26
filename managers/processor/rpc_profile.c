/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/slab.h>
#include <lego/math64.h>
#include <lego/timer.h>
#include <lego/kernel.h>
#include <lego/kthread.h>
#include <lego/syscalls.h>
#include <lego/profile.h>
#include <lego/fit_ibapi.h>
#include <processor/zerofill.h>
#include <processor/processor.h>
#include <processor/distvm.h>
#include <processor/vnode.h>
#include <processor/pcache.h>

#define MAX_SEND_LEN	(PAGE_SIZE * 4)
#define MAX_REPLY_LEN	(PAGE_SIZE * 4)
#define NR_TESTS	(100000)

static void profile_case_noreply(char *desc, int send_len, int reply_len,
				 void *send_buf, void *reply_buf,
				 unsigned int dst_nid)
{
	int i;
	struct p2m_test_msg *msg;
	unsigned long start_ns, end_ns, total_ns, avg_ns;

	msg = send_buf;
	fill_common_header(msg, P2M_TEST_NOREPLY);
	msg->send_len = send_len;
	msg->reply_len = reply_len;

	start_ns = sched_clock();
	for (i = 0; i < NR_TESTS; i++) {
		ibapi_send(dst_nid, msg, msg->send_len);
	}
	end_ns = sched_clock();

	total_ns = end_ns - start_ns;
	avg_ns = total_ns / NR_TESTS;

	pr_info("    CPU%2d Profile: %s. Avg: %lu ns.\n",
		smp_processor_id(), desc, avg_ns);
}

static void profile_case(char *desc, int send_len, int reply_len,
		      void *send_buf, void *reply_buf, unsigned int dst_nid)
{
	int i;
	struct p2m_test_msg *msg;
	unsigned long start_ns, end_ns, total_ns, avg_ns;

	msg = send_buf;
	fill_common_header(msg, P2M_TEST);
	msg->send_len = send_len;
	msg->reply_len = reply_len;

	start_ns = sched_clock();
	for (i = 0; i < NR_TESTS; i++) {
		ibapi_send_reply_timeout(dst_nid,
				 	msg, msg->send_len,
					reply_buf, MAX_REPLY_LEN,
					false, 10);
	}
	end_ns = sched_clock();

	total_ns = end_ns - start_ns;
	avg_ns = total_ns / NR_TESTS;

	pr_info("    CPU%2d Profile: %s. Avg: %lu ns.\n",
		smp_processor_id(), desc, avg_ns);
}

struct profile_info {
	char *desc;
	int send_len, reply_len;
	void *send_buf, *reply_buf;
	unsigned int dst_nid;
	int nr_threads;
};

static atomic_t barrier;
static atomic_t exit_barrier;

static int __profile_case_threads(void *_info)
{
	struct profile_info *info = _info;

	/* A simple barrier to sync between threads */
	atomic_dec(&barrier);
	while (atomic_read(&barrier))
		schedule();


	profile_case(info->desc, info->send_len, info->reply_len,
		     info->send_buf, info->reply_buf, info->dst_nid);
	profile_case_noreply(info->desc, info->send_len, info->reply_len,
		     info->send_buf, info->reply_buf, info->dst_nid);

	atomic_dec(&exit_barrier);
	return 0;
}

static void
profile_case_threads(char *desc, int send_len, int reply_len,
		     unsigned int dst_nid, unsigned int nr_threads)
{
	struct task_struct *tsk;
	struct profile_info *info;
	void *send_buf, *reply_buf;
	int i;

	pr_info("RPC Profile. [Peer node: %d. nr_threads: %d. nr_run/case: %d. send: %d reply %d]\n",
		dst_nid, nr_threads, NR_TESTS, send_len, reply_len);

	info = kmalloc(nr_threads * sizeof(*info), GFP_KERNEL);
	if (!info) {
		pr_err("Fail to alloc info\n");
		return;
	}

	atomic_set(&barrier, nr_threads);
	atomic_set(&exit_barrier, nr_threads);

	for (i = 0; i < nr_threads; i++) {
		send_buf = kmalloc(MAX_SEND_LEN, GFP_KERNEL);
		reply_buf = kmalloc(MAX_REPLY_LEN, GFP_KERNEL);
		if (!send_buf || !reply_buf) {
			pr_err("Fail to alloc buf\n");
			return;
		}

		info[i].desc = desc;
		info[i].send_len = send_len;
		info[i].reply_len = reply_len;
		info[i].send_buf = send_buf;
		info[i].reply_buf = reply_buf;
		info[i].dst_nid = dst_nid;
		info[i].nr_threads = nr_threads;

		tsk = kthread_run(__profile_case_threads, &info[i], "rpc_profile_thread");
		if (IS_ERR(tsk)) {
			pr_err("Fail to create profile thread");
			return;
		}
	}

	/*
	 * Wait until all threads finished profiling
	 * In case we are running on a non-preemptive kernel,
	 * use schedule() intead of ;, because the worker thread
	 * may end up running on this same core.
	 *
	 * And you know non-preemptive kernel, right? The kernel
	 * thread will NOT ever got re-scheduled until it yield.
	 */
	while (atomic_read(&exit_barrier))
		schedule();
}

static unsigned int send_size[] = {
	32,	/* has to be larger than p2m_test_msg */
	128,
	256,
	512,
	1024,
	2048,
	4096,
	4200,	/* pcache_flush send case. reply is 4B */
};

static unsigned int reply_size[] = {
	4,
	32,
	128,
	256,
	512,
	1024,
	2048,
	4096,	/* pcache_miss reply case. send is around 20B */
};

void rpc_profile_node(unsigned int nid)
{
	void *send_buf, *reply_buf;
	int i, j, send, reply;
	char desc[128];

	send_buf = kmalloc(MAX_SEND_LEN, GFP_KERNEL);
	reply_buf = kmalloc(MAX_REPLY_LEN, GFP_KERNEL);
	if (!send_buf || !reply_buf) {
		pr_err("OOM!");
		return;
	}

	/*
	 * We have three variables
	 * - send length
	 * - reply length
	 * - nr_threads
	 */
	for (i = 0; i < ARRAY_SIZE(send_size); i++) {
		for (j = 0; j < ARRAY_SIZE(reply_size); j++) {
			send = send_size[i];
			reply = reply_size[j];

			memset(desc, 0, 128);
			snprintf(desc, 128, "s%4d-r%4d", send, reply);

			profile_case_threads(desc, send, reply, nid, 1);
			profile_case_threads(desc, send, reply, nid, 2);
			profile_case_threads(desc, send, reply, nid, 4);
		}
	}

	profile_case("pcache_miss",
		  sizeof(struct p2m_pcache_miss_msg), PCACHE_LINE_SIZE,
		  send_buf, reply_buf, nid);

	profile_case("pcache_flush",
		  sizeof(struct p2m_flush_msg), sizeof(int),
		  send_buf, reply_buf, nid);
}

enum _rpc_profile_state {
	RPC_PROFILE_BOOT,
	RPC_PROFILE_WIP,
	RPC_PROFILE_DONE,
};

static int rpc_profile_state = RPC_PROFILE_BOOT;

void rpc_profile(void)
{
	rpc_profile_state = RPC_PROFILE_WIP;

	rpc_profile_node(CONFIG_DEFAULT_MEM_NODE);

	rpc_profile_state = RPC_PROFILE_DONE;
}

void wait_rpc_profile(void)
{
	while (rpc_profile_state != RPC_PROFILE_DONE)
		;
}
