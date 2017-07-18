/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _INCLUDE_FIT_API_H
#define _INCLUDE_FIT_API_H

#include <lego/types.h>
#include <lego/errno.h>
#include <net/arch/cc.h>

/* 
 * change the following for each node
 * wuklab04: 0
 * wuklab06: 1
 * wuklab08: 2
 */
#define MY_NODE_ID 1

#ifdef CONFIG_FIT
int ibapi_establish_conn(int ib_port, int mynodeid);
void ibapi_free_recv_buf(void *input_buf);

//uint64_t ibapi_dist_barrier(unsigned int checknum);

/* IMM related */
int ibapi_reply_message(void *addr, int size, uintptr_t descriptor);
int ibapi_send_reply_imm(int target_node, void *addr, int size, void *ret_addr, int max_ret_size, int if_use_ret_phys_addr);
int ibapi_receive_message(unsigned int designed_port, void *ret_addr, int receive_size, uintptr_t *descriptor);

int ibapi_get_node_id(void);
int ibapi_num_connected_nodes(void);

#else
static inline int ibapi_reply_message(void *addr, int size, uintptr_t descriptor)
{ return -EIO; }
static inline int ibapi_send_reply_imm(int target_node, void *addr, int size,
				       void *ret_addr, int max_ret_size, bool if_use_ret_phys_addr)
{ return -EIO; }
static inline int ibapi_receive_message(unsigned int designed_port, void *ret_addr,
					int receive_size, uintptr_t *descriptor)
{ return -EIO; }
static inline int ibapi_get_node_id(void) {return 0; }
static inline int ibapi_num_connected_nodes(void) {return 0; };
#endif /* CONFIG_FIT*/

#endif /* _INCLUDE_FIT_API_H */
