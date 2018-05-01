/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/jiffies.h>

#include <common.h>
#include <gmm.h>

static LIST_HEAD(mnodes);
static struct task_struct *status_polling;

static struct mnode_struct *get_mnode(unsigned int nid)
{
	struct mnode_struct *pos, *target = NULL;
	list_for_each_entry(pos, &mnodes, list) {
		if (pos->nid == nid) {
			target = pos;
			break;
		}
	}
	return target;
}

int handle_m2mm_consult(struct consult_info *payload, u64 desc, struct common_header *hdr)
{
	unsigned int src_nid = hdr->src_nid;
	unsigned long len = payload->len;
	unsigned long freeram = payload->freeram;
	unsigned long totalram = payload->totalram;
	unsigned long nr_request = payload->nr_request;
	unsigned int nid = 0;
	int ret = 0;
	struct consult_reply reply;
	struct mnode_struct *mnode;

	/* update memory status */
	mnode = get_mnode(src_nid);
	if (mnode) {
		mnode->totalram = totalram;
		mnode->freeram = freeram;
		mnode->nr_request = nr_request;
	} else {
		pr_warn("Invalid memory node!");
	}

	/* choose node for request */
	nid = choose_node();
	pr_info("New memory request, length: %lx, memory chosen: %d\n", len, nid);

	reply.count = 1;
	reply.scheme[0].nid = nid;
	reply.scheme[0].len = len;

#if USE_IBAPI
	ret = ibapi_reply_message(&reply, sizeof(reply), desc);
#endif
	return ret;
}
EXPORT_SYMBOL(handle_m2mm_consult);

static inline void prepare_memstatus_payload(struct m2mm_mnode_status *send)
{
	static int counter = 0;
	counter++;

	send->counter = counter;
	send->hdr.opcode = M2MM_STATUS_REPORT;
	send->hdr.src_nid = LEGO_LOCAL_NID;
}

static int request_memory_nodes_status(void *unused)
{
	int ret = 0;
	struct mnode_struct *pos;
	struct m2mm_mnode_status send;
	struct m2mm_mnode_status_reply reply;

	while (1) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(1);
		__set_current_state(TASK_RUNNING);

		prepare_memstatus_payload(&send);
		pr_info("Request New Status: NR %d\n", send.counter);

		list_for_each_entry(pos, &mnodes, list) {
#if USE_IBAPI
			ret = ibapi_send_reply_imm(pos->nid, &send, sizeof(send),
						   &reply, sizeof(reply), 0);
#endif
			if (ret < 0) {
				pr_info("couldn't retrieve memory information from node %d\n",
					pos->nid);
				continue;
			}

			pos->totalram = reply.totalram;
			pos->freeram = reply.freeram;
			pos->nr_request = reply.nr_request;
			pr_info("    Node %d, new freeram: %lx, new totalram: %lx, nr_request: %ld\n",
				pos->nid, pos->freeram, pos->totalram, pos->nr_request);
		}
	}
	return 0;
}

int choose_node(void)
{
#if PURE_RR_CHOOSE
	static int rr_counter = 0;
	rr_counter++;
	return mnode_nids[rr_counter / RR_CHOOSE_INTERVAL % MEMORY_NODE_COUNT];
#endif

#if NETWORK_TRAFFIC_RR_CHOOSE
	static int rr_counter = -1;
	static int last_time_choose = 0;
	struct mnode_struct *mnode, *target;

	rr_counter++;
	if (rr_counter % RR_CHOOSE_INTERVAL)
		return last_time_choose;

	/* choose the one with least network traffic */
	target = list_first_entry(&mnodes, struct mnode_struct, list);
	list_for_each_entry(mnode, &mnodes, list) {
		pr_info("nid: %d, nr_request: %ld", mnode->nid, mnode->nr_request);
		if (mnode->nr_request <= target->nr_request)
			target = mnode;
	}
	last_time_choose = target->nid;
	return target->nid;
#endif

#if RESIDENT_MEMORY_CHOOSE
	struct mnode_struct *mnode, *target;

	target = list_first_entry(&mnodes, struct mnode_struct, list);
	list_for_each_entry(mnode, &mnodes, list) {
		if (mnode->freeram > target->freeram)
			target = mnode;
	}
	return target->nid;
#endif
}
EXPORT_SYMBOL(choose_node);

static int lego_mnode_conn_setup(void)
{
	int i;
	struct mnode_struct *m;

	for (i = 0; i < MEMORY_NODE_COUNT; i++) {
		m = kmalloc(sizeof(struct mnode_struct), GFP_KERNEL);
		if (unlikely(!m))
			return -ENOMEM;

		m->nid = mnode_nids[i];
		m->totalram = 0;
		m->freeram = 0;
		m->nr_request = 0;
		list_add_tail(&m->list, &mnodes);
		pr_info("memory node with id %d is online\n", m->nid);
	}
	return 0;
}

static int __init lego_gmm_module_init(void)
{
	int ret;

	pr_info("lego memory monitor module init is called.\n");
	ret = lego_mnode_conn_setup();
	if (ret)
		return ret;
#if MNODES_STATUS_REQUEST
	status_polling = kthread_run(request_memory_nodes_status,
				     NULL, "request_memory_nodes_status");
	return IS_ERR(status_polling);
#else
	return 0;
#endif
}

/*
 * Lego global memory monitor exit
 */
static void mnodes_free(void)
{
	struct mnode_struct *m, *n;
	list_for_each_entry_safe(m, n, &mnodes, list) {
		list_del(&m->list);
		kfree(m);
	}
}

static void __exit lego_gmm_module_exit(void)
{
	mnodes_free();
#if MNODES_STATUS_REQUEST
	kthread_stop(status_polling);
#endif
	pr_info("lego memory monitor module exit\n");
}

module_init(lego_gmm_module_init);
module_exit(lego_gmm_module_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wuklab@Purdue");
