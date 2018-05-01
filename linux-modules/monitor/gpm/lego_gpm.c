/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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
#include <linux/kernel.h>
#include <linux/kthread.h>

#include <gpm.h>
#include <gmm.h>

static LIST_HEAD(pnodes);
static struct vnode_struct vnode_map[VNODE_MAP_SIZE];

/*
 * functions serve PM2P_START_PROC
 * details refer to include/monitor/common.h
 */

/* processor monitor policy making function */
static struct pnode_struct *pick_one_pnode(void)
{
	__u32 min = INT_MAX;
	struct pnode_struct *p;
	struct pnode_struct *target = NULL;
	list_for_each_entry(p, &pnodes, list) {
		if (p->proc_count < min) {
			min = p->proc_count;
			target = p;
		}
	}
	return target;
}

static int get_vpid(void)
{
	/* TODO: generate global pid */
	return 1;
}

static struct proc_struct *find_proc(int vpid)
{
	struct proc_struct *proc;
	struct pnode_struct *pnode;

	/* not many nodes, just walk through list */
	list_for_each_entry(pnode, &pnodes, list) {
		list_for_each_entry(proc, &pnode->proclist, proclist) {
			if (proc->vpid == vpid)
				return proc;
		}
	}
	return NULL;
}

static int prep_start_proc_payload(int size, char *cmd, char *sendbuf)
{
	struct common_header *hdr;
	struct pm2p_start_proc_struct *info;
	char *cmdsent;

	memset(sendbuf, 0, MAX_RXBUF_SIZE);
	hdr = (struct common_header *)sendbuf;
	info = (struct pm2p_start_proc_struct *)info_offset(sendbuf);
	cmdsent = cmd_offset(sendbuf);

	hdr->opcode = PM2P_START_PROC;
	hdr->src_nid = LEGO_LOCAL_NID;
	hdr->length = start_proc_msg_len(size);

	info->vpid = get_vpid();
	info->homenode = choose_node();
	if (info->homenode < 0) {
		pr_warn("NO MEMORY COMPONENT EXISTS\n");
		return -EPERM;
	}

	memcpy(cmdsent, cmd, size);
	return info->vpid;
}

int lego_proc_create(char *command, int size)
{
	int ret = -ENOMEM, reply = 0;
	char *sendbuf;
	struct pnode_struct *target_pnode;
	struct proc_struct *proc;

	target_pnode = pick_one_pnode();
	pr_info("CMD: '%s' assigned to node %d\n", command, target_pnode->nid);

	/* keep some program information */
	proc = kmalloc(sizeof(*proc), GFP_KERNEL);
	if (!proc)
		return -ENOMEM;

	proc->command = kmalloc(size, GFP_KERNEL);
	if (!proc->command)
		goto free_cmd;

	memcpy(proc->command, command, size);

	/* start preparing send payload */
	sendbuf = kmalloc(start_proc_msg_len(size), GFP_KERNEL);
	if (!sendbuf)
		goto free_proc;

	/* TODO: need to check vpid is valid */
	proc->vpid = prep_start_proc_payload(size, command, sendbuf);
	if (proc->vpid < 0) {
		ret = proc->vpid;
		goto bad;
	}

	proc->pnode = target_pnode;
	list_add_tail(&proc->proclist, &target_pnode->proclist);
#if USE_IBAPI
	ret = ibapi_send_reply_imm(target_pnode->nid, sendbuf,
				start_proc_msg_len(size), &reply, sizeof(int), 0);
	pr_debug("ibapi result: %d\n", ret);
#endif

	if (ret || reply) {
		ret = ret ? ret : reply;
		goto bad;
	}

	target_pnode->proc_count++;
	pr_info("%d running task on %d processor node\n",
			target_pnode->proc_count, target_pnode->nid);
	kfree(sendbuf);
	return 0;

bad:
	kfree(sendbuf);
free_proc:
	kfree(proc);
free_cmd:
	kfree(proc->command);
	return ret;
}
EXPORT_SYMBOL(lego_proc_create);

/*
 * functions serve PM2P_EXIT_PROC
 * details refer to include/monitor/common.h
 */
int handle_p2pm_exit_proc(struct p2pm_exit_proc_struct *payload,
			  uintptr_t desc, struct common_header *hdr)
{
	int reply = 0;
	int vpid = payload->vpid;
	struct pnode_struct *pnode;
	struct proc_struct *proc;

	pr_info("program exit, vpid: %d\n", vpid);

	proc = find_proc(vpid);
	if (!proc) {
		pr_warn("No vpid found, possibly initial process or BUG!");
		reply = -EINVAL;
		goto reply;
	}

	/* TODO: send process return value msg->ret to GUM */
	pnode = proc->pnode;
	pnode->proc_count--;
	list_del(&proc->proclist);
	kfree(proc->command);
	kfree(proc);

reply:
#if USE_IBAPI
	ibapi_reply_message(&reply, sizeof(int), desc);
#endif
	return reply;
}
EXPORT_SYMBOL(handle_p2pm_exit_proc);

/*
 * functions for P2PM_REQUEST_VNODE
 */

static struct pm2p_broadcast_vnode_struct *
prepare_broadcast_payload(int p_nid, int vid, int ip)
{
	struct pm2p_broadcast_vnode_struct *send;
	send = kmalloc(sizeof(struct pm2p_broadcast_vnode_struct), GFP_KERNEL);
	if (!send)
		return NULL;

	fill_common_header(send, PM2P_BROADCAST_VNODE);
	send->p_nid = p_nid;
	send->vid = vid;
	send->ip = ip;

	return send;
}

static int pm2p_broadcast_vnode(int p_nid, int vid, int ip)
{
	int ret = 0, reply = 0;
	struct pnode_struct *pos;
	struct pm2p_broadcast_vnode_struct *send;

	send = prepare_broadcast_payload(p_nid, vid, ip);
	if (!send)
		return -ENOMEM;

	list_for_each_entry(pos, &pnodes, list) {
		/* no need to send to the requesting processor node */
		if (pos->nid == p_nid)
			continue;

#if USE_IBAPI
		ret = ibapi_send_reply_imm(pos->nid, &send, sizeof(send),
					   &reply, sizeof(reply), 0);
#endif
		if (ret < 0 || reply) {
			pr_info("couldn't broadcast vnode update to node %d\n",
				pos->nid);
			break;
		}
	}

	kfree(send);
	return ret ? ret : reply;
}

/*
 * TODO: current vnode id is same as nid and IP address is
 * merely IP base address plus vid, need to change this later
 */
int handle_p2pm_request_vnode(struct p2pm_request_vnode_struct *req, uintptr_t desc)
{
	int nid  = req->hdr.src_nid;
	int vid = nid;
	int ip = IP_ADDRESS_BASE + vid;
	struct p2pm_request_vnode_reply_struct reply;

	vnode_map[vid].p_nid = nid;
	vnode_map[vid].vid = vid;
	vnode_map[vid].ip = ip;

	reply.status = 0;
	reply.p_nid = nid;
	reply.vid = vid;
	reply.ip = ip;

	reply.status = pm2p_broadcast_vnode(nid, vid, ip);
#if USE_IBAPI
	ibapi_reply_message(&reply, sizeof(reply), desc);
#endif

	pr_info("New vnode updated, p_nid: %d, vid: %d, ip: %x\n",
		nid, vid, ip);

	WARN_ON(vid >= VNODE_MAP_SIZE);

	return reply.status;
}
EXPORT_SYMBOL(handle_p2pm_request_vnode);

/*
 * lego global processor monitor initialization
 */
static int lego_pnode_conn_setup(void)
{
	int i;
	struct pnode_struct *p;

	for (i = 0; i < PROCESSOR_NODE_COUNT; i++) {
		p = kmalloc(sizeof(struct pnode_struct), GFP_KERNEL);
		if (unlikely(!p))
			return -ENOMEM;

		p->nid = pnode_nids[i];
		/*
		 * TODO: physical number of core should be got from processor node,
		 * currently only statically set
		 */
		p->core_count = 24;
		p->proc_count = 0;
		INIT_LIST_HEAD(&p->proclist);
		list_add_tail(&p->list, &pnodes);
		pr_info("processor node with node_id %d is online\n", p->nid);
	}
	return 0;
}

static int __init lego_gpm_module_init(void)
{
	int ret;

	pr_info("lego processor monitor module init called.\n");
	ret = lego_pnode_conn_setup();
	return ret;
}

/*
 * Lego global processor monitor exit
 */
static void proc_structs_free(struct pnode_struct *p)
{
	struct proc_struct *proc, *n;
	list_for_each_entry_safe(proc, n, &p->proclist, proclist) {
		list_del(&proc->proclist);
		kfree(proc);
	}
}

static void pnodes_free(void)
{
	struct pnode_struct *p, *n;
	list_for_each_entry_safe(p, n, &pnodes, list) {
		proc_structs_free(p);
		list_del(&p->list);
		kfree(p);
	}
}

static void __exit lego_gpm_module_exit(void)
{
	pnodes_free();
	pr_info("lego processor monitor module exit\n");
}

module_init(lego_gpm_module_init);
module_exit(lego_gpm_module_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wuklab@Purdue");
