/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "gsm.h"

int handle_p2sm_alloc_nodes(int *payload, uintptr_t desc)
{
	int vid = *payload;
	struct lego_vnode_struct *mm_vnode;
	struct gsm2p_ret_struct res;
	int ret = 0;

	res.mid = -1;
	res.sid = -1;

	mm_vnode = ht_find_lego_vnode(vid);
	if (!mm_vnode) {
		mm_vnode = alloc_lego_vnode(vid, alloc_sid(vid));
		if (unlikely(!mm_vnode)) {
			ret = -ENOMEM;
			goto reply;
		}

		ht_insert_lego_vnode(mm_vnode);
	}
	
	res.sid = mm_vnode->storage_node_id;

	if (mm_vnode->pgcache_node_id == -1) {
		/* TODO:
		 * should be determined by GMM
		 * now always let mem node DEFAULT_MEM_HOMENODE as page cache node
		 */
		mm_vnode->pgcache_node_id = DEFAULT_MEM_HOMENODE;
	}
	res.mid = mm_vnode->pgcache_node_id;
reply:
	ibapi_reply_message(&res, sizeof(res), desc);
	return ret;
}
EXPORT_SYMBOL(handle_p2sm_alloc_nodes);
