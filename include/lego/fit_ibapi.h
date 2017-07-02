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

#include <net/arch/cc.h>
#define MY_NODE_ID 1

#if 0
int ibapi_reg_send_handler(int (*input_funptr)(char *addr, uint32_t length, int sender_id));
int ibapi_reg_send_reply_handler(int (*input_funptr)(char *input_buf, uint32_t size, char *output_buf, uint32_t *output_size, int sender_id));
int ibapi_reg_send_reply_opt_handler(int (*input_funptr)(char *input_buf, uint32_t size, void **output_buf, uint32_t *output_size, int sender_id));
int ibapi_reg_send_reply_rdma_imm_handler(int (*input_funptr)(int sender_id, void *msg, uint32_t size, uint32_t inbox_addr, uint32_t inbox_rkey, uint32_t inbox_semaphore));
#endif
int ibapi_establish_conn(int ib_port, int mynodeid);

inline void ibapi_free_recv_buf(void *input_buf);

//uint64_t ibapi_dist_barrier(unsigned int checknum);

//IMM related
inline int ibapi_reply_message(void *addr, int size, uintptr_t descriptor);
//int ibapi_query_port(int target_node, int designed_port, int requery_flag);
inline int ibapi_send_reply_imm(int target_node, void *addr, int size, void *ret_addr, int max_ret_size);
inline int ibapi_receive_message(unsigned int designed_port, void *ret_addr, int receive_size, uintptr_t *descriptor);

int ibapi_get_node_id(void);
int ibapi_num_connected_nodes(void);

#endif
