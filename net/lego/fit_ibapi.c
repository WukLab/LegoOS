/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/net.h>
#include <lego/slab.h>
#include <lego/sched.h>
#include <rdma/ib_verbs.h>
#include <lego/fit_ibapi.h>
#include <lego/completion.h>
#include <lego/profile.h>
#include "fit.h"
#include "fit_internal.h"

#define HANDLER_LENGTH 0
#define HANDLER_INTERARRIVAL 0

//#define DEBUG_IBV
#ifdef TEST_PRINTK
#define test_printk(x...)	pr_crit(x)
#else
#define test_printk(x...)	do {} while (0)
#endif

#define SRCADDR INADDR_ANY
#define DSTADDR ((unsigned long int)0xc0a87b01) /* 192.168.123.1 */

int num_parallel_connection = NUM_PARALLEL_CONNECTION;
atomic_t global_reqid;
ppc *FIT_ctx;
int curr_node;
struct ib_device *ibapi_dev;
struct ib_pd *ctx_pd;

static void ibv_add_one(struct ib_device *device)
{
	FIT_ctx = kmalloc(sizeof(struct lego_context), GFP_KERNEL);
	ibapi_dev = device;

	ctx_pd = ib_alloc_pd(device);
	if (!ctx_pd) {
		printk(KERN_ALERT "Couldn't allocate PD\n");
	}

	return;
}

static void ibv_remove_one(struct ib_device *device)
{
	return;
}

#ifdef CONFIG_FIT_SEQUENTIAL_IBAPI
static DEFINE_SPINLOCK(ibapi_send_reply_lock);
static inline void lock_ib(void)
{
	spin_lock(&ibapi_send_reply_lock);
}
static inline void unlock_ib(void)
{
	spin_unlock(&ibapi_send_reply_lock);
}
#else
static inline void lock_ib(void) { }
static inline void unlock_ib(void) { }
#endif

unsigned long	nr_recvcq_cqes[NUM_POLLING_THREADS];
#ifdef CONFIG_COUNTER_FIT_IB
atomic_long_t	nr_ib_send_reply;
atomic_long_t	nr_ib_send;
atomic_long_t	nr_bytes_tx;
atomic_long_t	nr_bytes_rx;

void dump_ib_stats(void)
{
	int i;

	pr_info("IB Stats:\n");
	pr_info("    nr_ib_send_reply: %15ld\n", COUNTER_nr_ib_send_reply());
	pr_info("    nr_ib_send:       %15ld\n", COUNTER_nr_ib_send());
	for (i = 0; i < NUM_POLLING_THREADS; i++)
		pr_info("      recvcq[0] CQEs: %15lu\n", nr_recvcq_cqes[i]);
	pr_info("    nr_bytes_tx:      %15ld\n", COUNTER_nr_bytes_tx());
	pr_info("    nr_bytes_rx:      %15ld\n", COUNTER_nr_bytes_rx());
}
#endif

DEFINE_PROFILE_POINT(ibapi_send_reply)

static inline int
__ibapi_send_reply_timeout(int target_node, void *addr, int size, void *ret_addr,
			   int max_ret_size, int if_use_ret_phys_addr,
			   unsigned long timeout_sec, void *caller)
{
	ppc *ctx = FIT_ctx;
	int ret;
        PROFILE_POINT_TIME(ibapi_send_reply)

        PROFILE_START(ibapi_send_reply);

	if (unlikely(target_node >= CONFIG_FIT_NR_NODES)) {
		pr_info("target_node: %d\n", target_node);
		BUG();
	}

	lock_ib();
	ret = fit_send_reply_with_rdma_write_with_imm(ctx, target_node, addr,
			size, ret_addr, max_ret_size, 0, if_use_ret_phys_addr,
			timeout_sec, caller);

	if (unlikely(ret > max_ret_size)) {
		pr_info("ret: %d, max_ret_size: %d\n", ret, max_ret_size);
		BUG();
	}
	unlock_ib();

#ifdef CONFIG_COUNTER_FIT_IB
	atomic_long_inc(&nr_ib_send_reply);
	atomic_long_add(size, &nr_bytes_tx);
	atomic_long_add(ret, &nr_bytes_rx);
#endif

        PROFILE_LEAVE(ibapi_send_reply);
	return ret;
}

/* Default to use maximum timeout */
int ibapi_send_reply_imm(int target_node, void *addr, int size, void *ret_addr,
			 int max_ret_size, int if_use_ret_phys_addr)
{
	return __ibapi_send_reply_timeout(target_node, addr, size, ret_addr,
			max_ret_size, if_use_ret_phys_addr, FIT_MAX_TIMEOUT_SEC,
			__builtin_return_address(0));
}

/**
 * ibapi_send_reply_timeout
 * @target_node: target node id
 * @addr
 * @size
 * @ret_addr
 * @max_ret_size
 * @if_use_ret_phys_addr:
 * @timeout_sec:
 *
 * Return:
 * Negative values on failure (-ETIMEDOUT for timeout)
 * Positive values indicate the reply message length
 */
int ibapi_send_reply_timeout(int target_node, void *addr, int size, void *ret_addr,
			     int max_ret_size, int if_use_ret_phys_addr,
			     unsigned long timeout_sec)
{
	return __ibapi_send_reply_timeout(target_node, addr, size, ret_addr,
			max_ret_size, if_use_ret_phys_addr, timeout_sec,
			__builtin_return_address(0));
}

static inline int
__ibapi_send_reply_timeout_w_private_bits(int target_node, void *addr, int size, void *ret_addr,
			   int max_ret_size, int *private_bits, int if_use_ret_phys_addr,
			   unsigned long timeout_sec, void *caller)
{
	ppc *ctx = FIT_ctx;
	int ret;

	ret = fit_send_reply_with_rdma_write_with_imm_reply_extra_bits(ctx, target_node, addr,
			size, ret_addr, max_ret_size, private_bits, 0, if_use_ret_phys_addr,
			timeout_sec, caller);

	return ret;
}

DEFINE_PROFILE_POINT(ibapi_send)

int ibapi_send(int target_node, void *addr, int size)
{
	int ret;
	PROFILE_POINT_TIME(ibapi_send)

#ifdef CONFIG_COUNTER_FIT_IB
	atomic_long_inc(&nr_ib_send);
	atomic_long_add(size, &nr_bytes_tx);
#endif

	PROFILE_START(ibapi_send);
	ret = fit_send_with_rdma_write_with_imm(FIT_ctx, target_node, addr, size, 0);
	PROFILE_LEAVE(ibapi_send);
	return ret;
}

/**
 * ibapi_multicast_send_reply_timeout - issue a RDMA request with several sge request - mainly used for multicast in kernel
 * @ctx: fit context
 * @num_nodes: number of multicast node
 * @target_node: target node array
 * @sglist: message array to be sent to the nodes
 * @output_msg: array of reply message buffer
 * @timeout_sec: timeout value in seconds
 */
int ibapi_multicast_send_reply_timeout(int num_nodes, int *target_node,
				struct fit_sglist *sglist, struct fit_sglist *output_msg,
				int max_ret_size, int if_use_ret_phys_addr, unsigned long timeout_sec)
{
	ppc *ctx = FIT_ctx;
	int ret;

	ret = fit_multicast_send_reply(ctx, num_nodes, target_node, sglist,
			output_msg, max_ret_size, 0, if_use_ret_phys_addr,
			timeout_sec, __builtin_return_address(0));
	return ret;
}

inline int ibapi_receive_message(unsigned int designed_port,
		void *ret_addr, int receive_size, uintptr_t *descriptor)
{
	ppc *ctx = FIT_ctx;
	return fit_receive_message(ctx, designed_port, ret_addr, receive_size, descriptor, 0);
}

int ibapi_receive_message_no_reply(unsigned int designed_port,
		void *ret_addr, int receive_size)
{
	ppc *ctx = FIT_ctx;
	return fit_receive_message_no_reply(ctx, designed_port, ret_addr, receive_size, 0);
}

inline int ibapi_reply_message(void *addr, int size, uintptr_t descriptor)
{
	ppc *ctx = FIT_ctx;
	return fit_reply_message(ctx, addr, size, descriptor, 0, 1);
}

inline int ibapi_reply_message_w_extra_bits(void *addr, int size, int bits, uintptr_t descriptor)
{
	ppc *ctx = FIT_ctx;
	return fit_reply_message_w_extra_bits(ctx, addr, size, bits, descriptor, 0, 1);
}

inline int ibapi_reply_message_nowait(void *addr, int size, uintptr_t descriptor)
{
	ppc *ctx = FIT_ctx;
	return fit_reply_message(ctx, addr, size, descriptor, 0, 0);
}

inline int ibapi_reply_message_w_extra_bits_no_wait(void *addr, int size, int bits, uintptr_t descriptor)
{
	ppc *ctx = FIT_ctx;
	return fit_reply_message_w_extra_bits(ctx, addr, size, bits, descriptor, 0, 0);
}

#ifdef CONFIG_SOCKET_O_IB
int ibapi_sock_send_message(int target_node, int dest_port, int if_internal_port, void *buf, int size, unsigned long timeout_sec, int if_userspace)
{
	ppc *ctx = FIT_ctx;

	if (target_node == MY_NODE_ID || target_node > MAX_NODE) {
		pr_crit("%s: wrong target node %d\n", __func__, target_node);
		return -1;
	}

	return sock_send_message(ctx, target_node, dest_port, if_internal_port, buf, size, timeout_sec, if_userspace);
}

int ibapi_sock_receive_message(int *target_node, int port, uintptr_t *ret_addr, int receive_size, int if_userspace, int if_nonblock)
{
	ppc *ctx = FIT_ctx;
	return sock_receive_message(ctx, target_node, port, ret_addr, receive_size, if_userspace, if_nonblock);
}
#endif

#if 0
int ibapi_register_application(unsigned int designed_port, unsigned int max_size_per_message, unsigned int max_user_per_node, char *name, uint64_t name_len)
{
	ppc *ctx = FIT_ctx;
	return fit_register_application(ctx, designed_port, max_size_per_message, max_user_per_node, name, name_len);
}

int ibapi_unregister_application(unsigned int designed_port)
{
	ppc *ctx = FIT_ctx;
	return fit_unregister_application(ctx, designed_port);
}

int ibapi_query_port(int target_node, int designed_port, int requery_flag)
{
	ppc *ctx = FIT_ctx;
	return fit_query_port(ctx, target_node, designed_port, requery_flag);
}
#endif

#if 0
uint64_t ibapi_dist_barrier(unsigned int check_num)
{
	int i;
	ppc *ctx = FIT_ctx;
	int source = ctx->node_id;
	int num_alive_nodes = atomic_read(&ctx->num_alive_nodes);
	uintptr_t tempaddr;
	int priority = LOW_PRIORITY;
	//int connection_id;
	atomic_inc(&ctx->dist_barrier_counter);
	for(i=1;i<=num_alive_nodes;i++)//skip CD
	{
		if(i==ctx->node_id)
			continue;
		tempaddr = fit_ib_reg_mr_addr(ctx, &source, sizeof(int));
		fit_send_message_sge_UD(ctx, i, MSG_DIST_BARRIER, (void *)tempaddr, sizeof(int), 0, 0, priority);
	}
	//while(atomic_read(&ctx->dist_barrier_counter)<num_alive_nodes)
	while(atomic_read(&ctx->dist_barrier_counter)<check_num)
	{
		schedule();
	}
	atomic_sub(check_num, &ctx->dist_barrier_counter);
	return 0;
}
#endif

void ibapi_free_recv_buf(void *input_buf)
{
	//printk(KERN_CRIT "IB freeing post_receive_cache vaddr %p\n", input_buf);
	//kmem_cache_free(post_receive_cache, input_buf);
	//fit_free_recv_buf(input_buf);
	//kmem_cache_free(post_receive_cache, input_buf);
}

int ibapi_num_connected_nodes(void)
{
	if(!FIT_ctx)
	{
		printk(KERN_CRIT "%s: using FIT ctx directly since ctx is NULL\n", __func__);
		return atomic_read(&FIT_ctx->num_alive_nodes);
	}
	return atomic_read(&FIT_ctx->num_alive_nodes);
}

int ibapi_get_node_id(void)
{
	ppc *ctx;
	if(FIT_ctx)
	{
		ctx = FIT_ctx;
		return ctx->node_id;
	}
	return 0;
}

static struct ib_client ibv_client = {
	.name   = "ibv_server",
	.add    = ibv_add_one,
	.remove = ibv_remove_one
};

//#define FIT_TESTING

static void lego_ib_test(void)
{
#ifdef FIT_TESTING
	int ret, i;
	char *buf = kmalloc(4096, GFP_KERNEL);
	char *buf2 = kmalloc(4096, GFP_KERNEL);
	char *retb = kmalloc(4096, GFP_KERNEL);
	char *retb2 = kmalloc(4096, GFP_KERNEL);
	uintptr_t desc;
	struct fit_sglist send_sglist[2], reply_sglist[2];
	int nodes[2];

	pr_info("testing multicast IB mynode %d\n", MY_NODE_ID);
	if (MY_NODE_ID == 1) {
		for (i = 0; i < 10; i++) {
			ret = ibapi_receive_message(0, buf, 4096, &desc);
			pr_info("received message: [%c%c%c%c]\n", buf[0], buf[1], buf[2], buf[3]);
			retb[0] = '1';
			retb[1] = '2';
			retb[2] = '\0';
			ret = ibapi_reply_message(retb, 4096, desc);
		}
	} else if (MY_NODE_ID == 2) {
		for (i = 0; i < 10; i++) {
			ret = ibapi_receive_message(0, buf, 4096, &desc);
			pr_info("received message: [%c%c%c%c]\n", buf[0], buf[1], buf[2], buf[3]);
			retb[0] = '6';
			retb[1] = '7';
			retb[2] = '\0';
			ret = ibapi_reply_message(retb, 4096, desc);
		}
	} else {
		buf[0] = 'a';
		buf[1] = 'b';
		buf[2] = '\0';
		buf2[0] = 'x';
		buf2[1] = 'y';
		buf2[2] = '\0';
		//struct page *p = alloc_page();
		send_sglist[0].addr = buf;
		send_sglist[0].len = 4096;
		send_sglist[1].addr = buf2;
		send_sglist[1].len = 4096;
		reply_sglist[0].addr = retb;
		reply_sglist[0].len = 4096;
		reply_sglist[1].addr = retb2;
		reply_sglist[1].len = 4096;
		nodes[0] = 1;
		nodes[1] = 2;

		for (i = 0; i < 10; i++) {
		ret = ibapi_multicast_send_reply_timeout(2, nodes, send_sglist, reply_sglist, 4096, 0, 360);
			pr_info("%s(%2d) retbuf1: %s retbuf2: %s\n", __func__, i, retb, retb2);
		}
	}
#endif
}

__initdata DEFINE_COMPLETION(ib_init_done);

int lego_ib_init(void *unused)
{
	int ret;
	int nr_mad;

	/* Pass statically assigned info */
	atomic_set(&global_reqid, 0);
	init_global_lid_qpn();
	print_gloabl_lid();

	/*
	 * XXX
	 * What's the reason to wait again? 7 is magic number here.
	 *
	 * The mad_got_one is upated by ib_mad_completion_handler.
	 * It will be increased if we got a RECV message.
	 */
	nr_mad = 7;
	pr_info("Please wait for enough IB MAD (number: %d) ...\n", nr_mad);
	while (mad_got_one < nr_mad)
		schedule();

	ret = ib_register_client(&ibv_client);
	if (ret) {
		pr_err("couldn't register IB client\n");
		return ret;
	}

	/*
	 * Use port 1
	 */
	FIT_ctx = fit_establish_conn(ibapi_dev, 1, MY_NODE_ID);
	BUG_ON(!FIT_ctx);
	pr_info("FIT layer ready to go!\n");

	lego_ib_test();

	/* notify init that ib has done initialization */
	complete(&ib_init_done);
	return 0;
}
