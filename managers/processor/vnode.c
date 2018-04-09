/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "VNODE: " fmt

#include <lego/string.h>
#include <lego/fit_ibapi.h>
#include <processor/vnode.h>

#define VNODE_MAP_SIZE		(1 << CONFIG_VNODE_MAP_ORDER)

static struct vnode_struct vnode_map[VNODE_MAP_SIZE];
static DEFINE_HASHTABLE(vnode_table, CONFIG_VNODE_TABLE_ORDER);

static DEFINE_SPINLOCK(vnode_lock);

/* insert */
static void __insert_vnode_map(int p_nid, int vid, int ip)
{
	BUG_ON(VNODE_MAP_SIZE <= vid);
	spin_lock(&vnode_lock);
	vnode_map[vid].p_nid = p_nid;
	vnode_map[vid].vid = vid;
	vnode_map[vid].ip = ip;
	spin_unlock(&vnode_lock);
}

static void __insert_vnode_table(struct vnode_struct *vnode)
{
	spin_lock(&vnode_lock);
	INIT_HLIST_NODE(&vnode->node);
	hash_add(vnode_table, &vnode->node, vnode->ip);
	spin_unlock(&vnode_lock);
}

static inline void insert_vnode(int p_nid, int vid, int ip)
{
	__insert_vnode_map(p_nid, vid, ip);
	__insert_vnode_table(&vnode_map[vid]);
}

/* remove */
static void __remove_vnode_table(struct vnode_struct *vnode)
{
	spin_lock(&vnode_lock);
	hash_del(&vnode->node);
	spin_unlock(&vnode_lock);
}

static void __remove_vnode_map(struct vnode_struct *vnode)
{
	BUG_ON(VNODE_MAP_SIZE <= vnode->vid);
	spin_lock(&vnode_lock);
	memset(&vnode_map[vnode->vid], 0, sizeof(struct vnode_struct));
	spin_unlock(&vnode_lock);
}

static inline void remove_vnode(struct vnode_struct *vnode)
{
	__remove_vnode_table(vnode);
	__remove_vnode_map(vnode);
}

/* check */
/* since both vid and nid can be zero, use ip as reference */
inline bool vnode_exist(int vid)
{
	return vnode_map[vid].ip;
}

/* find */
struct vnode_struct *ip_find_vnode(int ip)
{
	struct vnode_struct *vnode = NULL;

	spin_lock(&vnode_lock);
	hash_for_each_possible(vnode_table, vnode, node, ip) {
		if (vnode->ip == ip)
			break;
	}
	spin_unlock(&vnode_lock);

	return vnode;
}

inline struct vnode_struct *vid_find_vnode(int vid)
{
	BUG_ON(VNODE_MAP_SIZE <= (unsigned int)vid);
	return &vnode_map[vid];
}

int request_vnode(void)
{
#ifdef CONFIG_GPM
	int len;
	struct p2pm_request_vnode_struct send;
	struct p2pm_request_vnode_reply_struct reply;

	fill_common_header(&send, P2PM_REQUEST_VNODE);

	pr_info("Request new vnode\n");
	len = ibapi_send_reply_timeout(CONFIG_GPM_NODEID, &send, sizeof(send),
				       &reply, sizeof(reply), false,
				       DEF_NET_TIMEOUT);

	pr_debug("len: %d, reply.status: %d\n", len, reply.status);
	if (unlikely(len < 0))
		return -EPERM;

	if (unlikely(reply.status))
		return reply.status;

	WARN_ON(vnode_exist(reply.vid));

	insert_vnode(reply.p_nid, reply.vid, reply.ip);
	pr_info("New vnode assigned, p_nid: %d, vid: %d, ip: %x\n",
		reply.p_nid, reply.vid, reply.ip);

	return reply.vid;

#else
	return -ETIMEDOUT;
#endif
}

void handle_pm2p_broadcast_vnode(struct pm2p_broadcast_vnode_struct *vnode, u64 desc)
{
	int reply = 0;

	if (unlikely(vnode_exist(vnode->vid))) {
		reply = -EFAULT;
		WARN_ON(1);
	}

	insert_vnode(vnode->p_nid, vnode->vid, vnode->ip);
	pr_info("New vnode updated, p_nid: %d, vid: %d, ip: %x\n",
		vnode->p_nid, vnode->vid, vnode->ip);

	ibapi_reply_message(&reply, sizeof(int), desc);
}
