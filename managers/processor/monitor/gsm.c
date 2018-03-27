/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
 
#include <lego/slab.h>
#include <lego/fit_ibapi.h>
#include <processor/processor.h>
#include <lego/comp_common.h>

#ifdef CONFIG_GSM
/* 
 * get_info_from_gsm: get pgcache/storage homenode from GSM
 * set cached copy of pgcache/storage homenode in task_struct
 * on success, return 0
 */
int get_info_from_gsm(int my_vnode_id)
{
	int retlen;
	u32 len_p2gsm_msg;
	int *vnode_in_payload;
	void *p2gsm_msg;
	u32 *p2gsm_opcode;
	struct gsm2p_ret_struct retbuf;

	len_p2gsm_msg = sizeof(*p2gsm_opcode) + sizeof(int);
	p2gsm_msg = kmalloc(len_p2gsm_msg, GFP_KERNEL);
	if (unlikely(!p2gsm_msg)) {
		return -ENOMEM;
	}
			
	p2gsm_opcode = p2gsm_msg;
	vnode_in_payload = p2gsm_msg + sizeof(*p2gsm_opcode);
	*p2gsm_opcode = P2GSM_COMMON;
	*vnode_in_payload = my_vnode_id;
		
	retlen = ibapi_send_reply_imm(CONFIG_GSM_HOMENODE, p2gsm_msg, len_p2gsm_msg,	\
			&retbuf, sizeof(retbuf), false);
	
	if (retlen != sizeof(retbuf)) {
		kfree(p2gsm_msg);
		return -EIO;
	}

	set_pgcache_home_node(current, retbuf.mid);
	set_storage_home_node(current, retbuf.sid);
	kfree(p2gsm_msg);
	return 0;
}
#endif	/* CONFIG_GSM */
