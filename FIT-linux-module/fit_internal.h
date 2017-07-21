/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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

inline void client_free_recv_buf(void *input_buf);

ppc *client_establish_conn(struct ib_device *ib_dev, int ib_port, int mynodeid);
int client_cleanup_module(void);

//The below functions in ibapi are required to modify based on these four
//int client_query_port(ppc *ctx, int target_node, int desigend_port, int requery_flag);
int client_send_reply_with_rdma_write_with_imm(ppc *ctx, int target_node, void *addr, int size, void *ret_addr, int max_ret_size, int userspace_flag, int if_use_ret_phys_addr);
int client_reply_message(ppc *ctx, void *addr, int size, uintptr_t descriptor, int userspace_flag);
int client_receive_message(ppc *ctx, unsigned int port, void *ret_addr, int receive_size, uintptr_t *reply_descriptor, int userspace_flag);

int fit_internal_init(void);
int fit_internal_cleanup(void);
#endif
