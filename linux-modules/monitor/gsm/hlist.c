/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "gsm.h"
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/hashtable.h>

#define GSM_HASH_SHIFT		10

static DEFINE_SPINLOCK(gsm_hash_lock);
static DEFINE_HASHTABLE(gsm_hash, GSM_HASH_SHIFT);

/* check before insert */
int ht_insert_lego_vnode(struct lego_vnode_struct *mm_vnode)
{
	struct lego_vnode_struct *p;

	if (IS_ERR_OR_NULL(mm_vnode))
		return -EFAULT;

	spin_lock(&gsm_hash_lock);
	hash_for_each_possible(gsm_hash, p, hlink, mm_vnode->vid) {
		if (unlikely(p->vid == mm_vnode->vid)) {
			spin_unlock(&gsm_hash_lock);
			return -EEXIST;
		}
	}
	hash_add(gsm_hash, &mm_vnode->hlink, mm_vnode->vid);
	log_vnode(mm_vnode, false);
	spin_unlock(&gsm_hash_lock);

	return 0;
}

/* remove from hashtable */
int ht_remove_lego_vnode(struct lego_vnode_struct *mm_vnode)
{
	if (IS_ERR_OR_NULL(mm_vnode))
		return -EINVAL;

	spin_lock(&gsm_hash_lock);
	hash_del(&mm_vnode->hlink);
	log_vnode(mm_vnode, true);
	kfree(mm_vnode);
	spin_unlock(&gsm_hash_lock);
	return 0;
}

/* find the vnode struct in hashtable */
struct lego_vnode_struct *ht_find_lego_vnode(int vid)
{
	struct lego_vnode_struct *mm_vnode;

	spin_lock(&gsm_hash_lock);
	hash_for_each_possible(gsm_hash, mm_vnode, hlink, vid) {
		if (likely(mm_vnode->vid == vid)) {
			spin_unlock(&gsm_hash_lock);
			return mm_vnode;
		}
	}
	spin_unlock(&gsm_hash_lock);
	return NULL;
}

int reconstruct_hash_table(struct file *log)
{
	size_t len_log, cur;

	if (IS_ERR_OR_NULL(log)) {
		pr_warn("No log file exist.\n");
		return -ENOENT;
	}

	len_log = i_size_read(log->f_inode);
	cur = 0;

	while(cur != len_log) {
		struct lego_vnode_struct *mm_vnode;
		struct raw_vnode_struct raw_vnode;
		size_t retlen;

		retlen = kernel_read(log, cur, (char *) &raw_vnode, sizeof(raw_vnode));
		if (unlikely(retlen != sizeof(raw_vnode)))
			return -EIO;

		if (!raw_vnode.valid) {
			mm_vnode = ht_find_lego_vnode(raw_vnode.vid);
			if (!mm_vnode) {
				cur += sizeof(raw_vnode);
				continue;
			}
			ht_remove_lego_vnode(mm_vnode);
		} else {
			mm_vnode = alloc_lego_vnode(raw_vnode.vid, raw_vnode.sid);
			if (unlikely(!mm_vnode))
				return -ENOMEM;
			
			pr_info("insert hashtable with vnode->(id: %d, sid: %d)\n",
					mm_vnode->vid, mm_vnode->storage_node_id);
			ht_insert_lego_vnode(mm_vnode);
		}

		cur += sizeof(raw_vnode);
	}

	return 0;

}

void clear_hash_table(void)
{
	int bkt;
	struct lego_vnode_struct *mm_vnode;
	struct hlist_node *tmp;

	spin_lock(&gsm_hash_lock);
	hash_for_each_safe(gsm_hash, bkt, tmp, mm_vnode, hlink) {
		hash_del(&mm_vnode->hlink);

		pr_info("free mm_vnode->(vid: %d, sid: %d)\n",
			mm_vnode->vid, mm_vnode->storage_node_id);
		kfree(mm_vnode);
	}

	spin_unlock(&gsm_hash_lock);

	if (hash_empty(gsm_hash))
		pr_info("Successfully free Hash Table.\n");
}
