/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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
#include <lego/atomic.h>
#include <net/arch/cc.h>

#include <uapi/fit.h>

#ifdef CONFIG_FIT_LOCAL_ID
#define MY_NODE_ID	CONFIG_FIT_LOCAL_ID
#else
#define MY_NODE_ID	0
#endif

#ifdef CONFIG_FIT

#ifdef CONFIG_COUNTER_FIT_IB
extern atomic_long_t	nr_ib_send_reply;
extern atomic_long_t	nr_ib_send;
extern atomic_long_t	nr_bytes_tx;
extern atomic_long_t	nr_bytes_rx;

static inline long COUNTER_nr_ib_send_reply(void)
{
	return atomic_long_read(&nr_ib_send_reply);
}

static inline long COUNTER_nr_ib_send(void)
{
	return atomic_long_read(&nr_ib_send);
}

static inline long COUNTER_nr_bytes_tx(void)
{
	return atomic_long_read(&nr_bytes_tx);
}

static inline long COUNTER_nr_bytes_rx(void)
{
	return atomic_long_read(&nr_bytes_rx);
}

void dump_ib_stats(void);
#else
static inline long COUNTER_nr_ib_send_reply(void)
{
	return 0;
}
static inline long COUNTER_nr_ib_send(void)
{
	return 0;
}
static inline long COUNTER_nr_bytes_tx(void)
{
	return 0;
}
static inline long COUNTER_nr_bytes_rx(void)
{
	return 0;
}

static inline void dump_ib_stats(void)
{

}
#endif

/* for multicast and maybe other address ranges */
struct fit_sglist {
	void *addr;
	int len;
};

void ibapi_free_recv_buf(void *input_buf);

/* IMM related */
#ifdef CONFIG_COMP_MEMORY
inline int ibapi_reply_message(void *addr, int size, uintptr_t descriptor);
#endif

inline int ibapi_reply_message_w_extra_bits(void *addr, int size, int bits, uintptr_t descriptor);
inline int ibapi_reply_message_nowait(void *addr, int size, uintptr_t descriptor);
inline int ibapi_reply_message_w_extra_bits_nowait(void *addr, int size, int bits, uintptr_t descriptor);
int ibapi_receive_message(unsigned int designed_port, void *ret_addr, int receive_size, uintptr_t *descriptor);

int ibapi_send(int target_node, void *addr, int size);

int ibapi_send_reply_imm(int target_node, void *addr, int size, void *ret_addr,
			 int max_ret_size, int if_use_ret_phys_addr);
int ibapi_receive_message_no_reply(unsigned int designed_port,
		void *ret_addr, int receive_size);

extern unsigned long sysctl_send_reply_max_timeout_sec;

int ibapi_send_reply_timeout(int target_node, void *addr, int size, void *ret_addr,
			     int max_ret_size, int if_use_ret_phys_addr,
			     unsigned long timeout_sec);
int ibapi_send_reply_timeout_w_private_bits(int target_node, void *addr, int size, void *ret_addr,
			     int max_ret_size, int *private_bits, int if_use_ret_phys_addr,
			     unsigned long timeout_sec);
int ibapi_multicast_send_reply_timeout(int num_nodes, int *target_node, 
				struct fit_sglist *sglist, struct fit_sglist *output_msg,
				int max_ret_size, int if_use_ret_phys_addr, unsigned long timeout_sec);

int ibapi_get_node_id(void);
int ibapi_num_connected_nodes(void);

#ifdef CONFIG_SOCKET_O_IB

int ibapi_sock_send_message(int target_node, int dest_port, int if_internal_port, void *buf, int size, unsigned long timeout_sec, int if_userspace); 
int ibapi_sock_receive_message(int *target_node, int port, uintptr_t *ret_addr, int ret_size, int if_userspace, int sock_type);

#define SOCK_IB_MAX_SEND_RECV_SIZE 4096*3

int get_internal_port(int target_node, int port);

/* Shared by poll, and epoll if configured */
int sock_set_write_ready(int target_node, int port);
int sock_set_read_ready(int target_node, int port, int size);
int sock_unset_read_ready(int target_node, int port, int size);

int sock_poll_callback(int target_node, int port);

#ifdef CONFIG_EPOLL
int sock_epoll_callback(int target_node, int port);
#endif

#endif /* CONFIG_SOCKET_O_IB */

#else

static inline int ibapi_reply_message(void *addr, int size, uintptr_t descriptor)
{ return -EIO; }

static inline int ibapi_send_reply_imm(int target_node, void *addr, int size,
				       void *ret_addr, int max_ret_size, bool if_use_ret_phys_addr)
{ return -EIO; }

static inline int ibapi_send_reply_timeout(int target_node, void *addr, int size,
				       void *ret_addr, int max_ret_size, bool if_use_ret_phys_addr,
				       unsigned long timeout_sec)
{ return -EIO; }

int ibapi_send_reply_timeout_w_private_bits(int target_node, void *addr, int size, void *ret_addr,
			     int max_ret_size, int *private_bits, int if_use_ret_phys_addr,
			     unsigned long timeout_sec);
{ return -EIO; }

int ibapi_multicast_send_reply_timeout(int num_nodes, int *target_node, 
				struct fit_sglist *sglist, struct fit_sglist *output_msg,
				int max_ret_size, int if_use_ret_phys_addr, unsigned long timeout_sec)
{ return -EIO; }

static inline int ibapi_receive_message(unsigned int designed_port, void *ret_addr,
					int receive_size, uintptr_t *descriptor)
{ return -EIO; }

static inline int ibapi_get_node_id(void) {return 0; }
static inline int ibapi_num_connected_nodes(void) {return 0; };
static inline int ibapi_sock_send_message(int target_node, int port, int if_internal_port, void *addr, int size, unsigned long timeout_sec, int if_userspace) {return 0; };
static inline int ibapi_sock_receive_message(int *target_node, int port, uintptr_t *ret_addr, int ret_size, int if_userspace, int sock_type) {return 0; };
#endif /* CONFIG_FIT*/

#endif /* _INCLUDE_FIT_API_H */
