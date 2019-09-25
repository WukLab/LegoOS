/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __LEGO_GSM_
#define __LEGO_GSM_

#include <linux/hashtable.h>
#include <asm/unistd.h>
#include <common.h>

#define NUM_STORAGE_NODE	2
#define DEFAULT_MEM_HOMENODE	1
extern int global_storage_id[NUM_STORAGE_NODE];

#define alloc_s_node(x)		(x % NUM_STORAGE_NODE)
#define alloc_sid(x)		(global_storage_id[alloc_s_node(x)])

struct lego_vnode_struct {
	int vid;
	int pgcache_node_id;
	int storage_node_id;

	struct hlist_node hlink;
};

struct raw_vnode_struct {
	int vid;
	int sid;
	bool valid;
};

struct gsm2p_ret_struct {
	int mid;
	int sid;
};

/* hlist.c */
int ht_insert_lego_vnode(struct lego_vnode_struct *mm_vnode);
int ht_remove_lego_vnode(struct lego_vnode_struct *mm_vnode);
struct lego_vnode_struct *ht_find_lego_vnode(int vid);
int reconstruct_hash_table(struct file *log);
void clear_hash_table(void);

/* core.c */
struct lego_vnode_struct *alloc_lego_vnode(int vid, int sid);
void log_vnode(struct lego_vnode_struct *mm_vnode, bool delete);

/* handlers.c */
int handle_p2sm_alloc_nodes(int *payload, uintptr_t desc);

#endif /* __LEGO_GSM_ */
