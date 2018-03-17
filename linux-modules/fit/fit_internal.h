/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _INCLUDE_FIT_INTERNAL_H
#define _INCLUDE_FIT_INTERNAL_H

#include "fit.h"

#define NUM_POLLING_THREADS 1

/* THREAD_HANDLER_MODEL - CHOOSE ONE*/
#define WAITING_QUEUE_IMPLEMENTATION
//#define IMPLEMENTATION_THREAD_SPAWN
//#define POLLING_THREAD_HANDLING_IMPLEMENTATION

#define ASK_MR_TABLE_HANDLING

/* POLLING OPTIONS - CHOOSE ONE*/
#define BUSY_POLL_MODEL
//#define NOTIFY_MODEL

/* send reply model*/
#define CPURELAX_MODEL
//#define SCHEDULE_MODEL
//#define ADAPTIVE_MODEL

/* send poll thread model */
//#define SEPARATE_SEND_POLL_THREAD

#ifdef CONFIG_SOCKET_O_IB
struct sock_recved_msg_metadata
{       
        uint32_t        source_node_id;
	uint32_t	offset;
	uint32_t	size;
	uint32_t	port;
	struct list_head list;
};
#endif

inline void fit_free_recv_buf(void *input_buf);

struct lego_context *fit_establish_conn(struct ib_device *ib_dev, int ib_port, int mynodeid);
int fit_cleanup_module(void);

//The below functions in ibapi are required to modify based on these four
//int fit_query_port(struct lego_context *ctx, int target_node, int desigend_port, int requery_flag);
int fit_send_reply_with_rdma_write_with_imm(struct lego_context *ctx, int target_node, void *addr, int size, void *ret_addr, int max_ret_size, int userspace_flag, int if_use_ret_phys_addr);
int fit_reply_message(struct lego_context *ctx, void *addr, int size, uintptr_t descriptor, int userspace_flag);
int fit_receive_message(struct lego_context *ctx, unsigned int port, void *ret_addr, int receive_size, uintptr_t *reply_descriptor, int userspace_flag);

int fit_internal_init(void);
int fit_internal_cleanup(void);

/* fit_machine.c */
void init_global_lid_qpn(void);
void print_gloabl_lid(void);
unsigned int get_node_global_lid(unsigned int nid);
unsigned int get_node_first_qpn(unsigned int nid);
void check_current_first_qpn(unsigned int qpn);

extern unsigned int global_lid[];
extern unsigned int first_qpn[];

int sock_send_message(struct lego_context *ctx, int targe_node, int port, int if_internal_port, void *buf, int size, unsigned long timeout_sec, int if_userspace);
int sock_receive_message(struct lego_context *ctx, int *target_node, int port, void *ret_addr, int receive_size, int if_userspace, int sock_type);
#endif
