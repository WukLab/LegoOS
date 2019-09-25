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
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/kthread.h>

const char *log_fname = "/home/yilun/lego-gsm-log";
static struct file *log;

int global_storage_id[NUM_STORAGE_NODE];

static void init_storage_lid(void)
{
	global_storage_id[0] = 2;
	global_storage_id[1] = 4;
}

void log_vnode(struct lego_vnode_struct *mm_vnode, bool delete)
{
	struct raw_vnode_struct raw_vnode;
	ssize_t ret;

	if (IS_ERR_OR_NULL(log))
		return;

	raw_vnode.vid = mm_vnode->vid;
	raw_vnode.sid = mm_vnode->storage_node_id;

	if (delete)
		raw_vnode.valid = false;
	else
		raw_vnode.valid = true;

	ret = kernel_write(log, (char *) &raw_vnode, sizeof(raw_vnode), log->f_pos);

	if (ret != sizeof(raw_vnode))
		pr_warn("Fail to log vnode");
}

struct lego_vnode_struct *alloc_lego_vnode(int vid, int sid)
{
	struct lego_vnode_struct *mm_vnode;
	mm_vnode = kmalloc(sizeof(*mm_vnode), GFP_KERNEL);
	if (!mm_vnode)
		return NULL;
	
	mm_vnode->vid = vid;
	mm_vnode->storage_node_id = sid;
	mm_vnode->pgcache_node_id = -1;

	return mm_vnode;
}

static int __init lego_gsm_module_init(void)
{

	init_storage_lid();
	log = filp_open(log_fname, O_RDWR | O_CREAT | O_APPEND, 0644);
	if (!IS_ERR_OR_NULL(log))
		reconstruct_hash_table(log);
	
	return 0;
}

static void __exit lego_gsm_module_exit(void)
{
	if (!IS_ERR_OR_NULL(log))
		filp_close(log, NULL);

	/* free hashtable */
	clear_hash_table();
	pr_info("Bye GSM!\n");
	return;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yilun");
module_init(lego_gsm_module_init);
module_exit(lego_gsm_module_exit);
