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

#undef pr_fmt
#define pr_fmt(fmt) "fit: " fmt

#include "fit.h"

/*
 * Number of recv_cq
 * Each recv_cq has its dedicated polling thread.
 * Configured at compile time.
 */
#define NUM_POLLING_THREADS		(CONFIG_FIT_NR_RECVCQ_POLLING_THREADS)

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

inline void fit_free_recv_buf(void *input_buf);

ppc *fit_establish_conn(struct ib_device *ib_dev, int ib_port, int mynodeid);
int fit_cleanup_module(void);

//The below functions in ibapi are required to modify based on these four
//int fit_query_port(ppc *ctx, int target_node, int desigend_port, int requery_flag);

struct fit_sglist;

int fit_send_reply_with_rdma_write_with_imm(ppc *ctx, int target_node, void *addr,
				int size, void *ret_addr, int max_ret_size, int userspace_flag,
				int if_use_ret_phys_addr, unsigned long timeout_sec, void *caller);
int fit_send_reply_with_rdma_write_with_imm_reply_extra_bits(ppc *ctx, int target_node, void *addr,
					       int size, void *ret_addr, int max_ret_size, int *ret_private_bits,
					       int userspace_flag, int if_use_ret_phys_addr,
					       unsigned long timeout_sec, void *caller);
int fit_multicast_send_reply(ppc *ctx, int num_nodes, int *target_node,
						struct fit_sglist *sglist, struct fit_sglist *output_msg,
						int max_ret_size, int userspace_flag, int if_use_ret_phys_addr,
						unsigned long timeout_sec, void *caller);

int fit_send_with_rdma_write_with_imm(ppc *ctx, int target_node, void *addr,
					       int size, int userspace_flag);
int fit_receive_message_no_reply(ppc *ctx, unsigned int port, void *ret_addr, int receive_size, int userspace_flag);

int fit_reply_message(ppc *ctx, void *addr, int size, uintptr_t descriptor, int userspace_flag, int if_poll_now);
int fit_reply_message_w_extra_bits(ppc *ctx, void *addr, int size, int private_bits, uintptr_t descriptor, int userspace_flag, int if_poll_now);
int fit_receive_message(ppc *ctx, unsigned int port, void *ret_addr, int receive_size, uintptr_t *reply_descriptor, int userspace_flag);

int fit_internal_init(void);
int fit_internal_cleanup(void);

/* fit_machine.c */
void init_global_lid_qpn(void);
void print_gloabl_lid(void);

unsigned int get_node_global_lid(unsigned int nid);
unsigned int get_node_first_qpn(unsigned int nid);

extern unsigned int global_lid[];
extern unsigned int first_qpn[];

int sock_send_message(ppc *ctx, int targe_node, int port, int if_internal_port, void *buf, int size, unsigned long timeout_sec, int if_userspace);
int sock_receive_message(ppc *ctx, int *target_node, int port, void *ret_addr, int receive_size, int if_userspace, int sock_type);
#endif /* _INCLUDE_FIT_INTERNAL_H */
