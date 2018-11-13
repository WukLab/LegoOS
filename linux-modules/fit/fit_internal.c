/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/sched.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
//#include <linux/semaphore.h>
//#include <linux/completion.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/jiffies.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <rdma/ib_verbs.h>

#include <asm/asm.h>
#include "fit_internal.h"

atomic_t global_sock_avail_recv_bufs;

enum ib_mtu fit_mtu_to_enum(int mtu)
{
	switch (mtu) {
	case 256:  return IB_MTU_256;
	case 512:  return IB_MTU_512;
	case 1024: return IB_MTU_1024;
	case 2048: return IB_MTU_2048;
	case 4096: return IB_MTU_4096;
	default:   return -1;
	}
}

enum ib_mtu mtu;
int                     sl;
static int              page_size;
int                     rcnt, scnt;
struct fit_data full_connect_data[MAX_CONNECTION];
struct fit_data my_QPset[MAX_CONNECTION];
int                     ib_port = 1;
//static struct task_struct **thread_poll_cq, *thread_handler;

struct lego_context **Connected_Ctx;
atomic_t Connected_FIT_Num;

int num_recvd_rdma_ring_mrs;

spinlock_t wq_lock;

spinlock_t sock_qp_lock[MAX_NODE];
spinlock_t connection_lock[MAX_CONNECTION];
spinlock_t connection_lock_pedal[MAX_CONNECTION];
spinlock_t multicast_lock; //only one multicast can be executed at a single time

struct send_and_reply_format request_list;

int fit_send_message_sge(struct lego_context *ctx, int connection_id, int type, void *addr, int size, uint64_t inbox_addr, uint64_t inbox_semaphore, int priority);
#if 0
//LOCK related
#define HASH_TABLE_SIZE_BIT 16
DEFINE_HASHTABLE(LOCK_QUEUE_HASHTABLE, HASH_TABLE_SIZE_BIT);
spinlock_t LOCK_QUEUE_HASHTABLE_LOCK[1<<HASH_TABLE_SIZE_BIT];
#endif

long long int Internal_Stat_Sum=0;
int Internal_Stat_Count=0;

#ifdef CONFIG_SOCKET_O_IB
int init_socket_over_ib(struct lego_context *ctx, int port, int rx_depth, int i)
{
	pr_info("%s mynodeid %d remote node %d\n", __func__, ctx->node_id, i);

	ctx->sock_send_cq[i] = ib_create_cq((struct ib_device *)ctx->context, NULL, NULL, NULL, rx_depth+1, 0);
	//ctx->send_cq[i] = ctx->send_cq[0];
	struct ib_qp_attr attr;
	struct ib_qp_init_attr init_attr = {
		.send_cq = ctx->sock_send_cq[i],
		.recv_cq = ctx->sock_recv_cq,
		.cap = {
			.max_send_wr = 1, //rx_depth + 2,
			//.max_send_wr = 12000,
			.max_recv_wr = rx_depth,
			.max_send_sge = 16,
			.max_recv_sge = 16
		},
		.qp_type = IB_QPT_RC,
		.sq_sig_type = IB_SIGNAL_REQ_WR
	};

	ctx->sock_qp[i] = ib_create_qp(ctx->pd, &init_attr);
	if(!ctx->sock_qp[i])
	{
		printk(KERN_ALERT "Fail to create sock_qp\n");
		return -EINVAL;
	}
	ib_query_qp(ctx->sock_qp[i], &attr, IB_QP_CAP, &init_attr);
	//if(init_attr.cap.max_inline_data >= size)
	//{
	//	ctx->send_flags |= IB_SEND_INLINE;
	//}

	struct ib_qp_attr attr1 = {
		.qp_state = IB_QPS_INIT,
		.pkey_index = 0,
		.port_num = port,
		.qp_access_flags = IB_ACCESS_REMOTE_WRITE|IB_ACCESS_REMOTE_READ|IB_ACCESS_LOCAL_WRITE|IB_ACCESS_REMOTE_ATOMIC,
		.path_mtu = IB_MTU_2048,
		.retry_cnt = 7,
		.rnr_retry = 7
	};
	if(ib_modify_qp(ctx->sock_qp[i], &attr1,
				IB_QP_STATE		|
				IB_QP_PKEY_INDEX	|
				IB_QP_PORT		|
				IB_QP_ACCESS_FLAGS))
	{
		printk(KERN_ALERT "Fail to modify sock_qp\n");
		ib_destroy_qp(ctx->sock_qp[i]);
		return -EINVAL;
	}

	pr_info("%s created sock_qp for %d\n", __func__, i);

	return 0;
}
#endif

int FIRST_QPN = CONFIG_FIT_FIRST_QPN;
static int aligned = false;
static void align_first_qpn(struct ib_pd *pd, struct ib_qp_init_attr *init_attr)
{
	struct ib_qp *qp;

	if (aligned)
		return;

next:
	qp = ib_create_qp(pd, init_attr);
	if (IS_ERR_OR_NULL(qp))
		panic("Fail to create QPs to align first QPN.");

	pr_debug("%s(): created QPN: %d\n", __func__, qp->qp_num);

	if (qp->qp_num == (FIRST_QPN - 1)) {
		aligned = true;
		return;
	} else if (qp->qp_num > (FIRST_QPN - 1))
		panic("Initial alloc qpn: %d. align qpn: %d",
			qp->qp_num, FIRST_QPN);
	else
		goto next;
}

struct lego_context *fit_init_ctx(int size, int rx_depth, int port, struct ib_device *ib_dev, int mynodeid)
{
	int i;
	int num_connections = MAX_CONNECTION;
	struct lego_context *ctx;
	int rem_node_id;

	printk(KERN_CRIT "%s\n", __func__);
	ctx = (struct lego_context*)kzalloc(sizeof(struct lego_context), GFP_KERNEL);
	if(!ctx)
	{
		printk(KERN_ALERT "FAIL to initialize ctx in fit_init_ctx\n");
		return NULL;
	}
	ctx->node_id = mynodeid;
	ctx->size = size;
	ctx->send_flags = IB_SEND_SIGNALED;
	ctx->rx_depth = rx_depth;
	ctx->num_connections = num_connections;
	ctx->num_node = MAX_NODE;
	ctx->num_parallel_connection = NUM_PARALLEL_CONNECTION;
	ctx->context = (struct ib_context *)ib_dev;
	if(!ctx->context)
	{
		printk(KERN_ALERT "Fail to initialize device / ctx->context\n");
		return NULL;
	}
	ctx->channel = NULL;
	ctx->pd = ib_alloc_pd(ib_dev);
	if(!ctx->pd)
	{
		printk(KERN_ALERT "Fail to initialize pd / ctx->pd\n");
		return NULL;
	}
	ctx->proc = ib_get_dma_mr(ctx->pd, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ);
	ctx->send_state = (enum s_state *)kmalloc(num_connections * sizeof(enum s_state), GFP_KERNEL);	
	ctx->recv_state = (enum r_state *)kmalloc(num_connections * sizeof(enum r_state), GFP_KERNEL);

	printk(KERN_CRIT "%s proc lkey %d rkey %d\n", __func__, ctx->proc->lkey, ctx->proc->rkey);

	//Customized part
	ctx->num_alive_connection = (atomic_t *)kmalloc(ctx->num_node*sizeof(atomic_t), GFP_KERNEL);
	atomic_set(&ctx->num_alive_nodes, 1);
	memset(ctx->num_alive_connection, 0, ctx->num_node*sizeof(atomic_t));
	for(i=0;i<ctx->num_node;i++)
		atomic_set(&ctx->num_alive_connection[i], 0);

	ctx->recv_num = (int *)kmalloc(ctx->num_connections*sizeof(int), GFP_KERNEL);
	memset(ctx->recv_num, 0, ctx->num_connections*sizeof(int));

	ctx->atomic_request_num = (atomic_t *)kmalloc(ctx->num_node*sizeof(atomic_t), GFP_KERNEL);
	memset(ctx->atomic_request_num, 0, ctx->num_node*sizeof(atomic_t));
	for(i=0;i<ctx->num_node;i++)
		atomic_set(&ctx->atomic_request_num[i], -1);

	atomic_set(&ctx->parallel_thread_num,0);
	atomic_set(&ctx->alive_connection, 0);
	atomic_set(&ctx->num_completed_threads, 0);

	ctx->atomic_buffer = (struct atomic_struct **)kmalloc(num_connections * sizeof(struct atomic_struct *), GFP_KERNEL);
	ctx->atomic_buffer_total_length = (int *)kmalloc(num_connections * sizeof(int), GFP_KERNEL);
	for(i=0;i<num_connections;i++)
		ctx->atomic_buffer_total_length[i]=0;
	ctx->atomic_buffer_cur_length = (int *)kmalloc(num_connections * sizeof(int), GFP_KERNEL);
	for(i=0;i<num_connections;i++)
		ctx->atomic_buffer_cur_length[i]=-1;

	ctx->cq = (struct ib_cq **)kmalloc(NUM_POLLING_THREADS * sizeof(struct ib_cq *), GFP_KERNEL);
	for(i=0;i<NUM_POLLING_THREADS;i++)
	{
		ctx->cq[i]=ib_create_cq((struct ib_device *)ctx->context, NULL, NULL, NULL, rx_depth*4+1, 0);
		if(!ctx->cq[i])
		{
			printk(KERN_ALERT "Fail to create cq at %d/ ctx->cq\n", i);
			return NULL;
		}
	}
	ctx->send_cq = (struct ib_cq **)kmalloc(num_connections * sizeof(struct ib_cq *), GFP_KERNEL);
	ctx->connection_count = (atomic_t *)kmalloc(num_connections * sizeof(atomic_t), GFP_KERNEL);
	for(i=0;i<num_connections;i++)
	{
		atomic_set(&ctx->connection_count[i], 0);
	}

#if 0
	//barrier setup
	atomic_set(&ctx->dist_barrier_counter, 0);
#endif

	printk(KERN_CRIT "%s before create qps numconnections %d\n", __func__, num_connections);
	ctx->qp = (struct ib_qp **)kmalloc(num_connections * sizeof(struct ib_qp *), GFP_KERNEL);
	if(!ctx->qp)
	{
		printk(KERN_ALERT "Fail to create master qp / ctx->qp\n");
		return NULL;
	}

#ifdef CONFIG_SOCKET_O_IB
	ctx->sock_send_cq = (struct ib_cq **)kmalloc(MAX_NODE * sizeof(struct ib_cq *), GFP_KERNEL);
	ctx->sock_qp = (struct ib_qp **)kmalloc(MAX_NODE * sizeof(struct ib_qp *), GFP_KERNEL);
	ctx->sock_recv_cq = ib_create_cq((struct ib_device *)ctx->context, NULL, NULL, NULL, rx_depth+1, 0);
	BUG_ON(!ctx->sock_send_cq || !ctx->sock_recv_cq || !ctx->sock_qp);
#endif

	for(i=0;i<num_connections;i++)
	{
#ifdef CONFIG_SOCKET_O_IB
		rem_node_id = i/(NUM_PARALLEL_CONNECTION+1);
		printk(KERN_CRIT "mynodeid %d i %d connecting node %d\n", ctx->node_id, i, rem_node_id);
		if (rem_node_id == ctx->node_id)
			continue;
		/* last one for every remote node is a socket qp */
		if (i % (NUM_PARALLEL_CONNECTION+1) == NUM_PARALLEL_CONNECTION) {
			init_socket_over_ib(ctx, port, rx_depth, rem_node_id);
			continue;
		}
#else
		rem_node_id = i/NUM_PARALLEL_CONNECTION;
		printk(KERN_CRIT "%s mynodeid %d i %d %d\n", __func__, ctx->node_id, i, rem_node_id);
		if (rem_node_id == ctx->node_id)
			continue;
#endif
		ctx->send_state[i] = SS_INIT;
		ctx->recv_state[i] = RS_INIT;

		ctx->send_cq[i] = ib_create_cq((struct ib_device *)ctx->context, NULL, NULL, NULL, rx_depth+1, 0);
		//ctx->send_cq[i] = ctx->send_cq[0];
		struct ib_qp_attr attr;
		struct ib_qp_init_attr init_attr = {
			.send_cq = ctx->send_cq[i],//ctx->cq
			.recv_cq = ctx->cq[i%NUM_POLLING_THREADS],
			.cap = {
				.max_send_wr = 1, //rx_depth + 2,
				//.max_send_wr = 12000,
				.max_recv_wr = rx_depth,
				.max_send_sge = 16,
				.max_recv_sge = 16
			},
			.qp_type = IB_QPT_RC,
			.sq_sig_type = IB_SIGNAL_REQ_WR
		};

		align_first_qpn(ctx->pd, &init_attr);
		ctx->qp[i] = ib_create_qp(ctx->pd, &init_attr);
		if(!ctx->qp[i])
		{
			printk(KERN_ALERT "Fail to create qp[%d]\n", i);
			return NULL;
		}
		ib_query_qp(ctx->qp[i], &attr, IB_QP_CAP, &init_attr);
		if(init_attr.cap.max_inline_data >= size)
		{
			ctx->send_flags |= IB_SEND_INLINE;
		}

		printk(KERN_CRIT "created qp %d qpn %d\n", i, ctx->qp[i]->qp_num);

		struct ib_qp_attr attr1 = {
			.qp_state = IB_QPS_INIT,
			.pkey_index = 0,
			.port_num = port,
			.qp_access_flags = IB_ACCESS_REMOTE_WRITE|IB_ACCESS_REMOTE_READ|IB_ACCESS_LOCAL_WRITE|IB_ACCESS_REMOTE_ATOMIC,
			.path_mtu = IB_MTU_2048,
			.retry_cnt = 7,
			.rnr_retry = 7
		};
		if(ib_modify_qp(ctx->qp[i], &attr1,
					IB_QP_STATE		|
					IB_QP_PKEY_INDEX	|
					IB_QP_PORT		|
					IB_QP_ACCESS_FLAGS))
		{
			printk(KERN_ALERT "Fail to modify qp[%d]\n", i);
			ib_destroy_qp(ctx->qp[i]);
			return NULL;
		}
		printk(KERN_CRIT "%s created qp %d\n", __func__, i);
	}

	/*
	 * In case the QPN differs from the wuklab_cluster table
	 * May happen in VM environment.
	 */
	check_current_first_qpn(ctx->qp[0]->qp_num);

	//Do IMM local ring setup (imm-send-reply)
	ctx->reply_ready_indicators = (void **)kmalloc(sizeof(void*)*IMM_NUM_OF_SEMAPHORE, GFP_KERNEL);
	ctx->reply_ready_indicators_bitmap = kzalloc(sizeof(unsigned long) * BITS_TO_LONGS(IMM_NUM_OF_SEMAPHORE), GFP_KERNEL);
	spin_lock_init(&ctx->reply_ready_indicators_lock);

	for(i=0;i<IMM_MAX_PORT;i++)
	{
		INIT_LIST_HEAD(&(ctx->imm_waitqueue_perport[i].list));
		spin_lock_init(&ctx->imm_waitqueue_perport_lock[i]);
		ctx->imm_perport_reg_num[i]=-1;
	}
	
#ifdef CONFIG_SOCKET_O_IB
	for(i = 0; i < SOCK_MAX_LISTEN_PORTS; i++)
	{
		INIT_LIST_HEAD(&(ctx->sock_imm_waitqueue_perport[i].list));
		spin_lock_init(&ctx->sock_imm_waitqueue_perport_lock[i]);
	}
#endif
	
#ifdef ADAPTIVE_MODEL
	ctx->imm_inbox_block_queue = (wait_queue_head_t*)kmalloc((IMM_NUM_OF_SEMAPHORE)*sizeof(wait_queue_head_t), GFP_KERNEL);
	for(i=0;i<IMM_NUM_OF_SEMAPHORE;i++)
	        init_waitqueue_head(&ctx->imm_inbox_block_queue[i]);
#endif
#ifdef SCHEDULE_MODEL
	ctx->thread_waiting_for_reply = (struct task_struct **)kzalloc(sizeof(struct task_struct*)*IMM_NUM_OF_SEMAPHORE, GFP_KERNEL);
#endif
	
	#if 0
	//Lock related
	atomic_set(&ctx->lock_num, 0);
	ctx->lock_data = kzalloc(sizeof(struct fit_lock_form)*FIT_MAX_LOCK_NUM, GFP_KERNEL);
	#endif
	return ctx;
}

struct lego_context *fit_init_interface(int ib_port, struct ib_device *ib_dev, int mynodeid)
{
	int	size = 4096;
	int	rx_depth = RECV_DEPTH;
	int	ret;
	struct lego_context *ctx;
	mtu = IB_MTU_2048;
	sl = 0;

	page_size = PAGE_SIZE;
	rcnt = 0;
	scnt = 0;
	ctx = fit_init_ctx(size,rx_depth,ib_port, ib_dev, mynodeid);
	if(!ctx)
	{
		printk(KERN_ALERT "Fail to do fit_init_ctx\n");
		return 0;
	}

retry:
	ret = ib_query_port((struct ib_device *)ctx->context, ib_port, &ctx->portinfo);
	if(ret<0)
	{
		printk(KERN_ALERT "Fail to query port\n");
	}
	
   	if (!ctx->portinfo.lid || ctx->portinfo.state != 4) {
		printk(KERN_CRIT "Couldn't get local LID %d state %d\n", ctx->portinfo.lid, ctx->portinfo.state);
		schedule();
		goto retry;
	}
	else
		printk(KERN_CRIT "got local LID %d\n", ctx->portinfo.lid);

	/*
	 * Sanity Check...
	 *
	 */
	if (ctx->portinfo.lid != get_node_global_lid(CONFIG_FIT_LOCAL_ID)) {
		pr_info("\n"
			"***\n"
			"*** ERROR\n"
			"*** Current LID: %d. Table LID: %d.\n"
			"*** Other machine will fail to connect.\n"
			"*** Please update the table to use the latest LID.\n"
			"***\n", ctx->portinfo.lid,
			get_node_global_lid(CONFIG_FIT_LOCAL_ID));
		return NULL;
	}

	printk(KERN_ALERT "I am here before return fit_init_interface\n");
	return ctx;

}

uintptr_t fit_ib_reg_mr_phys_addr(struct lego_context *ctx, void *addr, size_t length)
{
	struct ib_device *ibd = (struct ib_device*)ctx->context;
	return (uintptr_t)phys_to_dma(ibd->dma_device, (phys_addr_t)addr);
}

int pr_test=0;
struct ib_mr *proc_test;

struct fit_ibv_mr *fit_ib_reg_mr(struct lego_context *ctx, void *addr, size_t length, enum ib_access_flags access)
{
	struct fit_ibv_mr *ret;
	struct ib_mr *proc;
	
	/*
	if(pr_test==0)
	{
		access =IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_ATOMIC; 
		proc_test = ib_get_dma_mr(ctx->pd,access);
		pr_test++;
	}
	*/
	proc = ctx->proc; //proc_test;

	ret = (struct fit_ibv_mr *)kmalloc(sizeof(struct fit_ibv_mr), GFP_KERNEL);
	
	ret->addr = (void *)ib_dma_map_single((struct ib_device *)ctx->context, addr, length, DMA_BIDIRECTIONAL); 
	
	ret->length = length;
	ret->lkey = proc->lkey;
	ret->rkey = proc->rkey;
	ret->node_id = ctx->node_id;
	//printk(KERN_CRIT "%s length %d addr %p retaddr:%x lkey:%d rkey:%d\n", __func__, (int) length, addr, (unsigned int)ret->addr, ret->lkey, ret->rkey);
	return ret;
}

inline uintptr_t fit_ib_reg_mr_addr_phys(struct lego_context *ctx, void *addr, size_t length)
{
	return fit_ib_reg_mr_phys_addr(ctx, addr, length);
}

inline uintptr_t fit_ib_reg_mr_addr(struct lego_context *ctx, void *addr, size_t length)
{
	return (uintptr_t)ib_dma_map_single((struct ib_device *)ctx->context, addr, length, DMA_BIDIRECTIONAL); 
}

void fit_ib_dereg_mr_addr(struct lego_context *ctx, void *addr, size_t length)
{
	return ib_dma_unmap_single((struct ib_device *)ctx->context, (uint64_t)addr, length, DMA_BIDIRECTIONAL); 
	//return (uintptr_t)ib_dma_unmap_single((struct ib_device *)ctx->context, addr, length, DMA_BIDIRECTIONAL); 
}

void header_cache_free(void *ptr)
{
	//printk(KERN_CRIT "free %x\n", ptr);
// XXX	kmem_cache_free(header_cache, ptr);
}

void header_cache_UD_free(void *ptr)
{
	//printk(KERN_CRIT "free %x\n", ptr);
// XXX	kmem_cache_free(header_cache_UD, ptr);
}

static int fit_post_receives_message(struct lego_context *ctx, int connection_id, int depth)
{
	int i, ret;

	for(i=0;i<depth;i++)
	{
		struct ib_recv_wr wr, *bad_wr = NULL;
		wr.wr_id = i + (connection_id << CONNECTION_ID_PUSH_BITS_BASED_ON_RECV_DEPTH);
		wr.next = NULL;
		wr.sg_list = NULL;
		wr.num_sge = 0;

		ret = ib_post_recv(ctx->qp[connection_id], &wr, &bad_wr);
		if (ret) {
			pr_err("Fail to post_recv conn_id: %d, i: %d, depth: %d\n",
				connection_id, i, depth);
			WARN_ON(1);
			return ret;
		}
	}
	return depth;
}

struct page *pp;

#ifdef CONFIG_SOCKET_O_IB
int sock_post_receives_message(struct lego_context *ctx, int connection_id, int depth)
{
	int i, ret;

	for(i=0;i<depth;i++)
	{
		struct ib_recv_wr wr, *bad_wr = NULL;
		wr.wr_id = i + (connection_id << CONNECTION_ID_PUSH_BITS_BASED_ON_RECV_DEPTH);
		wr.next = NULL;
		wr.sg_list = NULL;
		wr.num_sge = 0;
		ib_post_recv(ctx->sock_qp[connection_id], &wr, &bad_wr);
		if (ret) {
			pr_err("Fail to post recv\n");
			WARN_ON(1);
			return ret;
		}
		//printk(KERN_CRIT "%s postrecv %d buffers wr_id %d\n", __func__, depth, wr.wr_id);
	}

	//printk(KERN_CRIT "%s: FIT_STAT post-receive %d bytes, %lld ns\n", __func__, POST_RECEIVE_CACHE_SIZE, fit_internal_stat(0, FIT_STAT_CLEAR));
	return depth;
}

#define SOCK_MAX_IB_RECV_SIZE 4096*3
int sock_post_receive_buffer(struct lego_context *ctx, int connection_id, int depth)
{
	int i;
	char *buf;
	uintptr_t addr;
	int size = SOCK_MAX_IB_RECV_SIZE;
	int ret;

	printk(KERN_CRIT "%s post %d buffers\n", __func__, depth);
	for(i=0;i<depth;i++)
	{
		struct ib_sge sge[1];

		buf = kmalloc(SOCK_MAX_IB_RECV_SIZE, GFP_KERNEL);
		addr = fit_ib_reg_mr_addr(ctx, buf, size);

		sge[0].addr = (uintptr_t)addr;
		sge[0].length = size;
		sge[0].lkey = ctx->proc->lkey;

		struct ib_recv_wr wr, *bad_wr = NULL;
		wr.wr_id = (uint64_t)buf;
		wr.next = NULL;
		wr.sg_list = sge;
		wr.num_sge = 1;
		ret = ib_post_recv(ctx->sock_qp[connection_id], &wr, &bad_wr);
		if (ret) {
			printk(KERN_CRIT "ERROR: %s post recv error %d i %d\n", 
				__func__, ret, i);
		}
		printk(KERN_CRIT "%s buf %p addr %p lkey %d\n", 
				__func__, buf, addr, ctx->proc->lkey);
	}

	//printk(KERN_CRIT "%s: FIT_STAT post-receive %d bytes, %lld ns\n", __func__, POST_RECEIVE_CACHE_SIZE, fit_internal_stat(0, FIT_STAT_CLEAR));
	return depth;
}
#endif

int fit_post_receives_message_with_buffer(struct lego_context *ctx, int connection_id, int depth)
{
	int i;
	char *buf, *header;
	uintptr_t header_addr;
	struct ibapi_post_receive_intermediate_struct *p_r_i_struct;
	uintptr_t addr;
	int size;
	int ret;

	printk(KERN_CRIT "%s conn %d post %d buffers\n", __func__, connection_id, depth);
#ifdef CONFIG_SOCKET_O_IB
	size = 2 * sizeof(struct fit_ibv_mr);
#else
	size = sizeof(struct fit_ibv_mr);
#endif
	for(i=0;i<depth;i++)
	{
		struct ib_sge sge[2];

		buf = kmalloc(sizeof(struct fit_ibv_mr), GFP_KERNEL);
		addr = fit_ib_reg_mr_addr(ctx, buf, size);
		header = kmalloc(sizeof(struct ibapi_header), GFP_KERNEL);
		header_addr = fit_ib_reg_mr_addr(ctx, header, sizeof(struct ibapi_header));
		p_r_i_struct = (struct ibapi_post_receive_intermediate_struct *)kmalloc(sizeof(struct ibapi_post_receive_intermediate_struct), GFP_KERNEL);
		p_r_i_struct->header = (uintptr_t)header;
		p_r_i_struct->msg = (uintptr_t)buf;

		printk(KERN_CRIT "%s pristruct %p header %p buf %p msg %p byf %p\n", __func__, p_r_i_struct, p_r_i_struct->header, buf, p_r_i_struct->msg, addr);
		sge[0].addr = (uintptr_t)header_addr;
		sge[0].length = sizeof(struct ibapi_header);
		sge[0].lkey = ctx->proc->lkey;
		sge[1].addr = (uintptr_t)addr;
		sge[1].length = size;
		sge[1].lkey = ctx->proc->lkey;

		struct ib_recv_wr wr, *bad_wr = NULL;
		wr.wr_id = (uint64_t)p_r_i_struct;
		wr.next = NULL;
		wr.sg_list = sge;
		wr.num_sge = 2;
		ret = ib_post_recv(ctx->qp[connection_id], &wr, &bad_wr);
		if (ret) {
			printk(KERN_CRIT "ERROR: %s post recv error %d conn %d i %d\n", 
				__func__, ret, connection_id, i);
		}
		printk(KERN_CRIT "%s header %p header_addr %p buf %p addr %p lkey %d\n", 
				__func__, header, header_addr, buf, addr, ctx->proc->lkey);
	}

	//printk(KERN_CRIT "%s: FIT_STAT post-receive %d bytes, %lld ns\n", __func__, POST_RECEIVE_CACHE_SIZE, fit_internal_stat(0, FIT_STAT_CLEAR));
	return depth;
}

#ifdef CONFIG_SOCKET_O_IB
int connect_sock_qp(struct lego_context *ctx, int connection_id, int port, enum ib_mtu mtu, int sl, int destlid, int destqpn)
{
	struct ib_qp_attr attr = {
		.qp_state	= IB_QPS_RTR,
		.path_mtu	= mtu,
		.dest_qp_num	= destqpn,
		.rq_psn		= 1,
		.max_dest_rd_atomic	= 1,
		.min_rnr_timer	= 12,
		.ah_attr	= {
			.dlid		= destlid,
			.sl		= sl,
			.src_path_bits	= 0,
			.port_num	= port
		}
	};

	if(ib_modify_qp(ctx->sock_qp[connection_id], &attr, 
				IB_QP_STATE	|
				IB_QP_AV	|
				IB_QP_PATH_MTU	|
				IB_QP_DEST_QPN	|
				IB_QP_RQ_PSN	|
				IB_QP_MAX_DEST_RD_ATOMIC	|
				IB_QP_MIN_RNR_TIMER))
	{
		printk(KERN_ALERT "Fail to modify QP to RTR at sock-qp\n");
		return 1;
	}


	attr.qp_state	= IB_QPS_RTS;
	attr.timeout	= 21;
	attr.retry_cnt	= 7;
	attr.rnr_retry	= 7;
	attr.sq_psn	= 1;
	attr.max_rd_atomic = 1;
	if(ib_modify_qp(ctx->sock_qp[connection_id], &attr,
				IB_QP_STATE	|
				IB_QP_TIMEOUT	|
				IB_QP_RETRY_CNT	|
				IB_QP_RNR_RETRY	|
				IB_QP_SQ_PSN	|
				IB_QP_MAX_QP_RD_ATOMIC))
	{
		printk(KERN_ALERT "Fail to modify QP to RTS at sock-qp\n");
		return 2;
	}

	printk(KERN_CRIT "%s connected sock-qp destqpn %d\n", __func__, destqpn);
	return 0;
}
#endif

int fit_connect_ctx(struct lego_context *ctx, int connection_id, int port, enum ib_mtu mtu, int sl, int destlid, int destqpn)
{
	struct ib_qp_attr attr = {
		.qp_state	= IB_QPS_RTR,
		.path_mtu	= mtu,
		.dest_qp_num	= destqpn,
		.rq_psn		= 1,
		.max_dest_rd_atomic	= 1,
		.min_rnr_timer	= 12,
		.ah_attr	= {
			.dlid		= destlid,
			.sl		= sl,
			.src_path_bits	= 0,
			.port_num	= port
		}
	};

	if(ib_modify_qp(ctx->qp[connection_id], &attr, 
				IB_QP_STATE	|
				IB_QP_AV	|
				IB_QP_PATH_MTU	|
				IB_QP_DEST_QPN	|
				IB_QP_RQ_PSN	|
				IB_QP_MAX_DEST_RD_ATOMIC	|
				IB_QP_MIN_RNR_TIMER))
	{
		printk(KERN_ALERT "Fail to modify QP to RTR at connection %d\n", connection_id);
		return 1;
	}


	attr.qp_state	= IB_QPS_RTS;
	attr.timeout	= 21;
	attr.retry_cnt	= 7;
	attr.rnr_retry	= 7;
	attr.sq_psn	= 1;
	attr.max_rd_atomic = 1; //was 1
	if(ib_modify_qp(ctx->qp[connection_id], &attr,
				IB_QP_STATE	|
				IB_QP_TIMEOUT	|
				IB_QP_RETRY_CNT	|
				IB_QP_RNR_RETRY	|
				IB_QP_SQ_PSN	|
				IB_QP_MAX_QP_RD_ATOMIC))
	{
		printk(KERN_ALERT "Fail to modify QP to RTS at connection %d\n", connection_id);
		return 2;
	}

	printk(KERN_CRIT "%s connected conn %d destqpn %d\n", __func__, connection_id, destqpn);
	return 0;
}

int get_global_qpn(int mynodeid, int remnodeid, int conn)
{
	int ret;
	int remote_first_qpn;

	remote_first_qpn = get_node_first_qpn(remnodeid);
	BUG_ON(!remote_first_qpn);

#ifdef CONFIG_SOCKET_O_IB
	/* +1 for sock_qp */
	if (remnodeid > mynodeid)
		ret = mynodeid * (NUM_PARALLEL_CONNECTION+1) + conn;
	else
		ret = (mynodeid - 1) * (NUM_PARALLEL_CONNECTION+1) + conn;
#else
	if (remnodeid > mynodeid)
		ret = mynodeid * (NUM_PARALLEL_CONNECTION) + conn;
	else
		ret = (mynodeid - 1) * (NUM_PARALLEL_CONNECTION) + conn;
#endif

	return ret + remote_first_qpn;
}

int init_global_connt = 0;

#ifdef CONFIG_SOCKET_O_IB
int sock_connect_nodes(struct lego_context *ctx, int rem_node_id, int mynodeid)
{
	int ret;
	int global_qpn;

	/* 
	 * sock_qp is the last qp created on every node 
	 * only one qp per remote node for socket
	 */
	global_qpn = get_global_qpn(ctx->node_id, rem_node_id, NUM_PARALLEL_CONNECTION);
	printk(KERN_ALERT "%s: mynode %d remnode %d remotelid %d remoteqpn %d\n", 
			__func__, ctx->node_id, rem_node_id, global_lid[rem_node_id], global_qpn);
retry:
	ret = connect_sock_qp(ctx, rem_node_id, ib_port, mtu, sl, global_lid[rem_node_id], global_qpn);
	if(ret)
	{
		printk("fail to connect to node %d sock conn\n", rem_node_id);
		goto retry;
	}

	/* post receive IMM buffers */
	sock_post_receives_message(ctx, rem_node_id, ctx->rx_depth);

	printk(KERN_ALERT "successfully connect sock to node %d\n", rem_node_id);
	return 0;
}
#endif

int fit_add_newnode(struct lego_context *ctx, int rem_node_id, int mynodeid)
{
	int i;
	int ret;
	int cur_connection;
	int global_qpn;

	for (i = 0; i < NUM_PARALLEL_CONNECTION; i++) {
#ifdef CONFIG_SOCKET_O_IB
		cur_connection = (rem_node_id * (ctx->num_parallel_connection + 1)) + atomic_read(&ctx->num_alive_connection[rem_node_id]);
#else
		cur_connection = (rem_node_id * ctx->num_parallel_connection) + atomic_read(&ctx->num_alive_connection[rem_node_id]);
#endif
		global_qpn = get_global_qpn(ctx->node_id, rem_node_id, i);
		printk(KERN_ALERT "%s: cur connection %d mynode %d remnode %d remotelid %d remoteqpn %d\n", 
				__func__, cur_connection, ctx->node_id, rem_node_id, global_lid[rem_node_id], global_qpn);
retry:
		ret = fit_connect_ctx(ctx, cur_connection, ib_port, mtu, sl, global_lid[rem_node_id], global_qpn);
		if(ret)
		{
			printk("fail to connect to node %d conn %d\n", rem_node_id, i);
			goto retry;
		}

		/* post receive buffers to get remote ring mrs, always through first conn */
		if (i == 0)
			fit_post_receives_message_with_buffer(ctx, cur_connection, 1); //ctx->num_node - 1);

		/* post receive buffers for IMM */
		fit_post_receives_message(ctx, cur_connection, ctx->rx_depth/2);

		atomic_inc(&ctx->num_alive_connection[rem_node_id]);
		atomic_inc(&ctx->alive_connection);
		if(atomic_read(&ctx->num_alive_connection[rem_node_id]) == NUM_PARALLEL_CONNECTION)
		{
			atomic_inc(&ctx->num_alive_nodes);
			//printk(KERN_CRIT "%s: complete %d connection %d\n", __func__, NUM_PARALLEL_CONNECTION, rem_dest.node_id);
		}

		init_global_connt++;
	}

#ifdef CONFIG_SOCKET_O_IB
	ret = sock_connect_nodes(ctx, rem_node_id, mynodeid);
	if (ret != 0) {
		pr_info("Error: can't connect socket QP between remote node %d and local node %d\n",
				rem_node_id, mynodeid);
		return ret;
	}
#endif

	pr_info("***  Successfully built QP for node %2d [LID: %d QPN: %d]\n",
		rem_node_id, get_node_global_lid(rem_node_id),
		get_node_first_qpn(rem_node_id));

	return 0;
}

inline int fit_find_qp_id_by_qpnum(struct lego_context *ctx, uint32_t qp_num)
{
	int i;

	for(i=0;i<ctx->num_connections;i++)
	{
#ifdef CONFIG_SOCKET_O_IB
		if (i / (NUM_PARALLEL_CONNECTION + 1) == ctx->node_id)
			continue;
		/* a socket qp */
		if (i % (NUM_PARALLEL_CONNECTION + 1) == NUM_PARALLEL_CONNECTION)
			continue;
#else
		if (i / NUM_PARALLEL_CONNECTION == ctx->node_id)
			continue;
#endif
		//printk(KERN_CRIT "[%s] qp i %d num_connection %d qp_num %d\n", __func__, i, ctx->num_connections, qp_num);
		if(ctx->qp[i]->qp_num==qp_num)
			return i;
	}
	return -1;
}

#ifdef CONFIG_SOCKET_O_IB
inline int fit_find_sock_qp_id_by_qpnum(struct lego_context *ctx, uint32_t qp_num)
{
	int i;
	
	for(i = 0; i < MAX_NODE; i++)
	{
		/* does not support loop back currently */
		if (i == CONFIG_FIT_LOCAL_ID)
			continue;
		if(ctx->sock_qp[i]->qp_num == qp_num)
			return i;
	}

	return -1;
}
#endif

inline int fit_find_node_id_by_qpnum(struct lego_context *ctx, uint32_t qp_num)
{
	int tmp = fit_find_qp_id_by_qpnum(ctx, qp_num);
	if(tmp>=0)
	{
		return tmp/NUM_PARALLEL_CONNECTION;
	}
	return -1;
}

/*
 * If we can not get the CQE within 20 seconds
 * There should be something wrong.
 */
#define FIT_POLL_SENDCQ_TIMEOUT_NS	(20000000000L)

int fit_internal_poll_sendcq(struct ib_cq *tar_cq, int connection_id, int *check)
{
#if SEPARATE_SEND_POLL_THREAD
	/* 
	 * using a separate thread to poll send cq
	 */
	while((*check)==SEND_REPLY_WAIT)
	{
		cpu_relax();
	}
	return 0;
#else
	/*
	 * use same send thread to poll send cq
	 */
	int ne, i;
	struct ib_wc wc[2];
	unsigned long start_ns;

	start_ns = sched_clock();
	do{
		ne = ib_poll_cq(tar_cq, 1, wc);
		if(ne < 0)
		{
			printk(KERN_ALERT "poll send_cq failed at connection %d\n", connection_id);
			return 1;
		}

		if (unlikely(sched_clock() - start_ns > FIT_POLL_SENDCQ_TIMEOUT_NS)) {
			pr_info_once("\n"
				"*****\n"
				"***** Fail to to get the CQE from send_cq after %ld seconds!\n"
				"***** This means the packet was lost and something went wrong\n"
				"***** with your NIC...\n"
				"***** connection_id: %d dest node: %d\n"
				"*****\n", FIT_POLL_SENDCQ_TIMEOUT_NS/NSEC_PER_SEC,
				connection_id, connection_id / NUM_PARALLEL_CONNECTION);
			WARN_ON_ONCE(1);
		}
	}while(ne<1);
	for(i=0;i<ne;i++)
	{
		if(wc[i].status!=IB_WC_SUCCESS)
		{
			printk(KERN_ALERT "send request failed at connection %d as %d\n", connection_id, wc[i].status);
			return 2;
		}
		else
			break;
	}
	return 0;
#endif
}

int fit_send_message_with_rdma_write_with_imm_request(struct lego_context *ctx, int connection_id, uint32_t input_mr_rkey, 
		uintptr_t input_mr_addr, void *addr, int size, int offset, uint32_t imm, enum mode s_mode, 
		struct imm_message_metadata *header, int userspace_flag)
{
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge[2];
	int ret;
	uintptr_t temp_addr;
	uintptr_t temp_header_addr;
	int poll_status = SEND_REPLY_WAIT;
	int flag=0;

	//printk(KERN_CRIT "%s conn %d rkey %d mraddr %lx addr %p size %d offset %d imm %d\n", 
	//		__func__, connection_id, input_mr_rkey, input_mr_addr, addr, size, offset, imm);
retry_send_imm_request:
	memset(&wr, 0, sizeof(struct ib_send_wr));
	memset(&sge, 0, sizeof(struct ib_sge));
	
	wr.sg_list = sge;
	wr.wr.rdma.remote_addr = (uintptr_t) (input_mr_addr+offset);
	wr.wr.rdma.rkey = input_mr_rkey;

	if(s_mode == FIT_SEND_MESSAGE_HEADER_AND_IMM)
	{
		wr.wr_id = (uint64_t)ctx->reply_ready_indicators[header->inbox_semaphore];//get the real wait_send_reply_id address from inbox information
		wr.send_flags = IB_SEND_SIGNALED;
		wr.num_sge = 2;
		wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;

		temp_header_addr = fit_ib_reg_mr_addr(ctx, header, sizeof(struct imm_message_metadata));
		wr.ex.imm_data = imm;
		
		sge[0].addr = temp_header_addr;
		sge[0].length = sizeof(struct imm_message_metadata);
		sge[0].lkey = ctx->proc->lkey;
		temp_addr = fit_ib_reg_mr_addr(ctx, addr, size);
		sge[1].addr = temp_addr;
		sge[1].length = size;
		sge[1].lkey = ctx->proc->lkey;
	}
	else if(s_mode == FIT_SEND_MESSAGE_IMM_ONLY)
	{
		wr.wr_id = (uint64_t)&poll_status;
		wr.send_flags = IB_SEND_SIGNALED;

		wr.num_sge = 1;
		wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;

		wr.ex.imm_data = imm;
		temp_addr = fit_ib_reg_mr_addr(ctx, addr, size);
		sge[0].addr = temp_addr;
		sge[0].length = size;
		sge[0].lkey = ctx->proc->lkey;
	}
	else if(s_mode == FIT_SEND_ACK_IMM_ONLY)
	{
		wr.wr_id = (uint64_t)&poll_status;
		wr.send_flags = IB_SEND_SIGNALED;

		wr.num_sge = 0;
		wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;

		wr.ex.imm_data = imm;
		/*
		temp_addr = fit_ib_reg_mr_addr(ctx, addr, size);
		sge[0].addr = temp_addr;
		sge[0].length = size;
		sge[0].lkey = ctx->proc->lkey;
		*/
	}
	else
	{
		printk(KERN_CRIT "%s: wrong mode %d - testing function\n", __func__, s_mode);
		return -1;
	}

	spin_lock(&connection_lock[connection_id]);
	//printk(KERN_CRIT "%s about to post send conn %d wr_id %d num_sge %d\n",
	//		__func__, connection_id, wr.wr_id, wr.num_sge);
	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	
	if(!ret)
	{
		fit_internal_poll_sendcq(ctx->send_cq[connection_id], connection_id, &poll_status);
	}
	else
	{
		printk(KERN_INFO "%s: send fail %d ret %d\n", __func__, connection_id, ret);
	}
	spin_unlock(&connection_lock[connection_id]);

	return 0;
}

inline int fit_get_connection_by_atomic_number(struct lego_context *ctx, int target_node, int priority)
{
#ifdef CONFIG_SOCKET_O_IB
	return atomic_inc_return(&ctx->atomic_request_num[target_node]) % (atomic_read(&ctx->num_alive_connection[target_node])) 
			+ (NUM_PARALLEL_CONNECTION +1) * target_node;
#else	
	return atomic_inc_return(&ctx->atomic_request_num[target_node]) % (atomic_read(&ctx->num_alive_connection[target_node])) 
			+ NUM_PARALLEL_CONNECTION * target_node;
#endif			
}

int fit_receive_message(struct lego_context *ctx, unsigned int port, void *ret_addr, int receive_size, uintptr_t *reply_descriptor, int userspace_flag)
{
	//This ret_addr is 
	struct imm_message_metadata *tmp;
	int get_size;
	int offset;
	int node_id;
	int ret = 0;
	struct imm_message_metadata *descriptor;
	struct imm_header_from_cq_to_port *new_request;
	int last_ack;
	int ack_flag=0;

	//printk(KERN_CRIT "%s port %d\n", __func__, port);
	while(1)
	{
		spin_lock(&ctx->imm_waitqueue_perport_lock[port]);
		if(!list_empty(&(ctx->imm_waitqueue_perport[port].list)))
		{
			//printk(KERN_CRIT "%s port %d got req\n", __func__, port);
			new_request = list_entry(ctx->imm_waitqueue_perport[port].list.next, struct imm_header_from_cq_to_port, list);
			list_del(&new_request->list);	
			spin_unlock(&ctx->imm_waitqueue_perport_lock[port]);
			break;
		}
		spin_unlock(&ctx->imm_waitqueue_perport_lock[port]);
		schedule();
	}

	offset = new_request->offset;
	node_id = new_request->source_node_id;
	//printk(KERN_CRIT "%s got new req offset %d sourcenode %d\n", __func__, offset, node_id);
	//free list
	// XXX kmem_cache_free(imm_header_from_cq_to_port_cache, new_request);

	//get buffer from hash table based on node and port
	
	tmp = (struct imm_message_metadata *)(ctx->local_rdma_recv_rings[node_id] + offset);
	get_size = tmp->size;
	//printk(KERN_CRIT "%s got msg size %d\n", __func__, get_size);
	//Check size
	if(get_size > receive_size || get_size == 0)
	{
		return SEND_REPLY_SIZE_TOO_BIG;
	}

	//do data memcpy
	memcpy(ret_addr, ((void *)tmp) + sizeof(struct imm_message_metadata), get_size);
	//printk(KERN_CRIT "%s: hash-%p offset-%x tmp-%p recv %s testport-%d testnodeid-%d\n", __func__, current_hash_ptr->addr, offset, tmp, ret_addr, tmp->designed_port, tmp->source_node_id);

	//Generate descriptor for future reply message
	descriptor = (struct imm_message_metadata *)kmalloc(sizeof(struct imm_message_metadata), GFP_KERNEL); //kmem_cache_alloc(imm_message_metadata_cache, GFP_KERNEL);
	BUG_ON(!descriptor);
	/*
	while(!descriptor)
	{
		printk(KERN_CRIT "%s: descriptor alloc fail\n", __func__);
		descriptor = (struct imm_message_metadata *)kmalloc(sizeof(struct imm_message_metadata), GFP_KERNEL); //kmem_cache_alloc(imm_message_metadata_cache, GFP_KERNEL);
	}
	*/

	//has to keep data in descriptor
	memcpy(descriptor, tmp, sizeof(struct imm_message_metadata));
	*reply_descriptor = (uintptr_t)descriptor;
	
	//do ack based on the last_ack_index, submit a request to waiting_queue_handler	
	//printk(KERN_CRIT "%s last_ack %d offset %d\n", __func__, last_ack, offset);
	spin_lock(&ctx->local_last_ack_index_lock[node_id]);
	last_ack = ctx->local_last_ack_index[node_id];
	if( (offset>= last_ack && offset - last_ack >= IMM_ACK_FREQ) || 
	    (offset< last_ack && offset + IMM_PORT_CACHE_SIZE - last_ack >= IMM_ACK_FREQ))
	{
		ack_flag = 1;
		ctx->local_last_ack_index[node_id] = offset;
	}
	spin_unlock(&ctx->local_last_ack_index_lock[node_id]);

	if(ack_flag)
	{	
		struct send_and_reply_format *pass = (struct send_and_reply_format *)kmalloc(sizeof(struct send_and_reply_format), GFP_KERNEL);
		//pass = kmem_cache_alloc(s_r_cache, GFP_KERNEL);
		pass->msg = (char*)node_id; //(char*)current_hash_ptr;
		pass->length = offset;
		pass->type = MSG_DO_ACK_INTERNAL;

		//printk(KERN_CRIT "%s add ack req offset %d\n", __func__, offset);
		spin_lock(&wq_lock);
		list_add_tail(&(pass->list), &request_list.list);
		spin_unlock(&wq_lock);
	}
	
	return get_size;
}

int fit_reply_message(struct lego_context *ctx, void *addr, int size, uintptr_t descriptor, int userspace_flag)
{
	struct imm_message_metadata *tmp = (struct imm_message_metadata *)descriptor;
	int re_connection_id = fit_get_connection_by_atomic_number(ctx, tmp->source_node_id, LOW_PRIORITY);
	unsigned long phys_addr;
	void *real_addr;
	struct ib_device *ibd = (struct ib_device *)ctx->context;

	fit_send_message_with_rdma_write_with_imm_request(ctx, re_connection_id, tmp->inbox_rkey, 
			tmp->inbox_addr, addr, size, 0, tmp->inbox_semaphore | IMM_SEND_REPLY_RECV, 
			FIT_SEND_MESSAGE_IMM_ONLY, NULL, FIT_KERNELSPACE_FLAG);
	// XXX kmem_cache_free(imm_message_metadata_cache, tmp);

	return 0;
}

#ifdef CONFIG_SOCKET_O_IB
int sock_receive_message(struct lego_context *ctx, int *target_node, int port, void *ret_addr, int receive_size, int if_userspace, int sock_type)
{
	int get_size = 0;
	int offset;
	int node_id;
	struct sock_recved_msg_metadata *new_request = NULL, *temp_entry;
	int last_ack;
	int ack_flag=0;
	int total_received_size = 0;

	printk(KERN_CRIT "port %d sock_type %x if_userspace %d\n", port, sock_type, if_userspace);

get_next_request:
	new_request = NULL;
	get_size = 0;

	while(1)
	{
		spin_lock(&ctx->sock_imm_waitqueue_perport_lock[port]);
		list_for_each_entry_safe(new_request, temp_entry, 
			&(ctx->sock_imm_waitqueue_perport[port].list), list)
		{
			//printk(KERN_CRIT "%s port %d got req\n", __func__, port);
			node_id = new_request->source_node_id;
			get_size = new_request->size;
			offset = new_request->offset;
			printk(KERN_CRIT "got new req offset %d sourcenode %d size %d\n", 
					offset, node_id, get_size);
			if(get_size > receive_size)
			{
				new_request->size -= receive_size;
				new_request->offset += receive_size;
				get_size = receive_size;
			}
			else
				list_del(&new_request->list);	
			break;
		}
		spin_unlock(&ctx->sock_imm_waitqueue_perport_lock[port]);

		if (get_size > 0)
			break;
		if ((sock_type & O_NONBLOCK) > 0) {
			printk(KERN_CRIT "nonblock break %d\n", total_received_size);
			return total_received_size;
		}
		schedule();
	}

	/* 
	 * got all current requests
	 * return immediately for non-block socket
	 */
	if ((sock_type & O_NONBLOCK) > 0 && get_size == 0) {
		printk(KERN_CRIT "nonblock socket return when running out of received buffer %d\n", total_received_size);
		return total_received_size;
	}

	total_received_size += get_size;
	
	*target_node = node_id;
	printk(KERN_CRIT "adjusted new req offset %d sourcenode %d size %d\n", 
			offset, node_id, get_size);
	//free list
	// XXX kmem_cache_free(imm_header_from_cq_to_port_cache, new_request);
	kfree(new_request);

	/*
	* copy incoming data to user buffer
	* size of int is for the internal port header 
	*/
	if (if_userspace) {
		int cp_ret;

		cp_ret = copy_to_user(ret_addr, ctx->local_sock_rdma_recv_rings[node_id] + offset, get_size);
		WARN_ON(cp_ret);
	} else
		memcpy(ret_addr, ctx->local_sock_rdma_recv_rings[node_id] + offset, get_size);
	printk(KERN_CRIT "offset-%d recv %s srcnodeid-%d\n", offset, ret_addr, node_id);

	//do ack based on the last_ack_index, submit a request to waiting_queue_handler	
	//printk(KERN_CRIT "%s last_ack %d offset %d\n", __func__, last_ack, offset);
	spin_lock(&ctx->local_sock_last_ack_index_lock[node_id]);
	last_ack = ctx->local_sock_last_ack_index[node_id];
	if( (offset>= last_ack && offset - last_ack >= IMM_ACK_FREQ) || 
	    (offset< last_ack && offset + IMM_PORT_CACHE_SIZE - last_ack >= IMM_ACK_FREQ))
	{
		ack_flag = 1;
		ctx->local_sock_last_ack_index[node_id] = offset;
	}
	spin_unlock(&ctx->local_sock_last_ack_index_lock[node_id]);

	if(ack_flag)
	{	
		struct send_and_reply_format *pass;

		pass = kmalloc(sizeof(*pass), GFP_KERNEL);
		if (!pass)
			return -ENOMEM;

		pass->msg = (void *)(long)node_id;
		pass->length = offset;
		pass->type = MSG_SOCK_DO_ACK_INTERNAL;

		printk(KERN_CRIT "add ack req node %d offset %d\n", node_id, offset);
		spin_lock(&wq_lock);
		list_add_tail(&(pass->list), &request_list.list);
		spin_unlock(&wq_lock);
	}
	
	if (total_received_size < receive_size) {
		printk(KERN_CRIT "go to next request received size %d total %d\n", total_received_size, receive_size);
		goto get_next_request;
	}

	return total_received_size;
}

int sock_send_message_with_rdma_imm(struct lego_context *ctx, int target_node, uint32_t input_mr_rkey, 
		uintptr_t input_mr_addr, void *addr, int size, int offset, uint32_t imm_data,
		void* header, int header_size, enum mode s_mode, int if_use_phys_addr_reg)
{
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge[2];
	int ret, i, ne;
	uintptr_t temp_addr, header_addr;
	int poll_status = SEND_REPLY_WAIT;
	struct ib_wc wc[1];

	printk(KERN_CRIT "%s target_node %d rkey %d mraddr %lx addr %p size %d offset %d imm-0x%x mode %d\n", 
			__func__, target_node, input_mr_rkey, input_mr_addr, addr, size, offset, imm_data, s_mode);
	memset(&wr, 0, sizeof(struct ib_send_wr));
	memset(&sge, 0, sizeof(struct ib_sge));
	
	wr.sg_list = sge;
	wr.wr.rdma.remote_addr = (uintptr_t) (input_mr_addr+offset);
	wr.wr.rdma.rkey = input_mr_rkey;

	printk(KERN_CRIT "wr: remotr_addr: %p, rkey: %#lx header %p header size %d\n",
			wr.wr.rdma.remote_addr, wr.wr.rdma.rkey, header, header_size);

	if(s_mode == FIT_SEND_MESSAGE_HEADER_AND_IMM)
	{
		wr.wr_id = (uint64_t)&poll_status;
		wr.send_flags = IB_SEND_SIGNALED;
		wr.num_sge = 2;
		wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;

		header_addr = fit_ib_reg_mr_addr(ctx, header, header_size);
		wr.ex.imm_data = imm_data;
		
		sge[0].addr = header_addr;
		sge[0].length = header_size;
		sge[0].lkey = ctx->proc->lkey;
		if (if_use_phys_addr_reg)
			temp_addr = fit_ib_reg_mr_addr_phys(ctx, addr, size);
		else
			temp_addr = fit_ib_reg_mr_addr(ctx, addr, size);
		sge[1].addr = temp_addr;
		sge[1].length = size;
		sge[1].lkey = ctx->proc->lkey;
	}
	else if(s_mode == FIT_SEND_MESSAGE_IMM_ONLY)
	{
		wr.wr_id = (uint64_t)&poll_status;
		wr.send_flags = IB_SEND_SIGNALED;

		wr.num_sge = 1;
		wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;

		wr.ex.imm_data = imm_data;
		if (if_use_phys_addr_reg)
			temp_addr = fit_ib_reg_mr_addr_phys(ctx, addr, size);
		else
			temp_addr = fit_ib_reg_mr_addr(ctx, addr, size);
		sge[0].addr = temp_addr;
		sge[0].length = size;
		sge[0].lkey = ctx->proc->lkey;
	}
	else if(s_mode == FIT_SEND_ACK_IMM_ONLY)
	{
		wr.wr_id = (uint64_t)&poll_status;
		wr.send_flags = IB_SEND_SIGNALED;

		wr.num_sge = 0;
		wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;

		wr.ex.imm_data = imm_data;
	}
	else
	{
		printk(KERN_CRIT "%s: wrong mode %d - testing function\n", __func__, s_mode);
		return -1;
	}

	spin_lock(&sock_qp_lock[target_node]);
	//printk(KERN_CRIT "%s about to post send conn %d wr_id %d num_sge %d\n",
	//		__func__, connection_id, wr.wr_id, wr.num_sge);
	ret = ib_post_send(ctx->sock_qp[target_node], &wr, &bad_wr);
	
	if(!ret)
	{
		do{
			ne = ib_poll_cq(ctx->sock_send_cq[target_node], 1, wc);
			if(ne < 0)
			{
				printk(KERN_ALERT "poll send_cq failed at send-qp\n");
				spin_unlock(&sock_qp_lock[target_node]);
				return 1;
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				printk(KERN_ALERT "send failed at send-qp as %d\n", wc[i].status);
				spin_unlock(&sock_qp_lock[target_node]);
				return 2;
			}
		}
	}
	else
	{
		spin_unlock(&sock_qp_lock[target_node]);
		printk(KERN_INFO "%s: send fail %d ret %d\n", __func__, target_node, ret);
	}
	spin_unlock(&sock_qp_lock[target_node]);

	return 0;
}

#endif

void *fit_alloc_memory_for_mr(unsigned int length)
{
	void *tempptr;
	tempptr = kmalloc(length, GFP_KERNEL);//Modify from kzalloc to kmalloc
	if(!tempptr)
		printk(KERN_CRIT "%s: alloc error\n", __func__);
	return tempptr;
}

/*
 * busy polls IMM
 */
static int fit_poll_cq(struct lego_context *ctx, struct ib_cq *target_cq)
{
	int ne;
	struct ib_wc wc[NUM_PARALLEL_CONNECTION];
	int i, connection_id;
	int node_id, port, offset;
	int semaphore, length, opcode;
	struct imm_message_metadata *descriptor; 
	char *addr;
	int type;
	struct send_and_reply_format *recv;
	struct imm_header_from_cq_to_port *tmp;

	while(1) {
		do {
			ne = ib_poll_cq(target_cq, NUM_PARALLEL_CONNECTION, wc);
			if (ne < 0) {
				printk(KERN_ALERT "poll CQ failed %d\n", ne);
				return 1;
			}
		} while (ne < 1);

		for (i = 0; i < ne; i++) {
			if (wc[i].status != IB_WC_SUCCESS) {
				pr_err("%s: failed status (%d) for wr_id %d\n",
					__func__, wc[i].status, (int) wc[i].wr_id);
				continue;
			}

			if ((int) wc[i].opcode == IB_WC_RECV) {
				struct ibapi_post_receive_intermediate_struct *p_r_i_struct = (struct ibapi_post_receive_intermediate_struct*)wc[i].wr_id;
				struct ibapi_header temp_header;

				memcpy(&temp_header, (void *)p_r_i_struct->header, sizeof(struct ibapi_header));
				addr = (char *)p_r_i_struct->msg;
				type = temp_header.type;

				if (type == MSG_SEND_RDMA_RING_MR) {
					memcpy(&ctx->remote_rdma_ring_mrs[temp_header.src_id],
						addr, sizeof(struct fit_ibv_mr));
#ifdef CONFIG_SOCKET_O_IB
					memcpy(&ctx->remote_sock_rdma_ring_mrs[temp_header.src_id],
						addr + sizeof(struct fit_ibv_mr), sizeof(struct fit_ibv_mr));
#endif
					num_recvd_rdma_ring_mrs++;

					pr_crit(" .. Node [%2d] Joined. Remote addr %p, rkey %d, num_recvd_rdma_ring_mrs %d\n", 
						temp_header.src_id, ctx->remote_rdma_ring_mrs[temp_header.src_id].addr, 
						ctx->remote_rdma_ring_mrs[temp_header.src_id].rkey, num_recvd_rdma_ring_mrs);
				}
			} else if((int) wc[i].opcode == IB_WC_RECV_RDMA_WITH_IMM) {
				node_id = GET_NODE_ID_FROM_POST_RECEIVE_ID(wc[i].wr_id);

				if(wc[i].wc_flags&&IB_WC_WITH_IMM) {
					if (wc[i].ex.imm_data & IMM_SEND_REPLY_SEND) {
						offset = wc[i].ex.imm_data & IMM_GET_OFFSET; 
						port = IMM_GET_PORT_NUMBER(wc[i].ex.imm_data);

						tmp = kmalloc(sizeof(struct imm_header_from_cq_to_port), GFP_KERNEL);
						if (!tmp) {
							WARN_ON(1);
							return -ENOMEM;
						}
						tmp->source_node_id = node_id;
						tmp->offset = offset;

						/* ibapi_receive_message will dequeue */
						spin_lock(&ctx->imm_waitqueue_perport_lock[port]);
						list_add_tail(&(tmp->list), &ctx->imm_waitqueue_perport[port].list);
						spin_unlock(&ctx->imm_waitqueue_perport_lock[port]);
					} else if (wc[i].ex.imm_data & IMM_ACK || wc[i].byte_len == 0) {
						/* Internal ACK */
						offset = wc[i].ex.imm_data & IMM_GET_OFFSET;

						recv = kmalloc(sizeof(struct send_and_reply_format), GFP_KERNEL);
						if (!recv) {
							WARN_ON(1);
							return -ENOMEM;
						}
						recv->src_id = node_id;
						recv->msg = (char *)offset;
						recv->type = MSG_DO_ACK_REMOTE;

						spin_lock(&wq_lock);
						list_add_tail(&(recv->list), &request_list.list);
						spin_unlock(&wq_lock);
					} else if (wc[i].ex.imm_data & IMM_SEND_REPLY_RECV) {
						length = wc[i].byte_len;
						semaphore = wc[i].ex.imm_data & IMM_GET_SEMAPHORE;
						if (semaphore < 0 || semaphore >= IMM_NUM_OF_SEMAPHORE) {
							pr_err("Wrong index: %d\n", semaphore);
							WARN_ON_ONCE(1);
							continue;
						}
						memcpy((void *)ctx->reply_ready_indicators[semaphore], &length, sizeof(int));

						ctx->reply_ready_indicators[semaphore] = NULL;
						clear_bit(semaphore, ctx->reply_ready_indicators_bitmap);
					} else {
						pr_err("Unknown wc[i].ex.imm_data: %#lx\n", wc[i].ex.imm_data);
						WARN_ON_ONCE(1);
					}
				} else {
					pr_err("Unknown wc_flags %#lx\n", wc[i].wc_flags);
					WARN_ON_ONCE(1);
				}
				
				if (GET_POST_RECEIVE_DEPTH_FROM_POST_RECEIVE_ID(wc[i].wr_id)%(ctx->rx_depth/4) == ((ctx->rx_depth/4)-1)) {
					connection_id = fit_find_qp_id_by_qpnum(ctx, wc[i].qp->qp_num);	
					if (connection_id == -1) {
						pr_crit("Error: cannot find qp number %d\n", wc[i].qp->qp_num);
						continue;
					}
					fit_post_receives_message(ctx, connection_id, ctx->rx_depth/4);
				}
			} else {
				connection_id = fit_find_qp_id_by_qpnum(ctx, wc[i].qp->qp_num);
				printk(KERN_ALERT "%s: connection %d Recv weird event as %d\n", __func__, connection_id, (int)wc[i].opcode);
			}
		}
	}
	return 0;
}

int fit_poll_cq_pass(void *in)
{
	struct thread_pass_struct *input = (struct thread_pass_struct *)in;
	//printk(KERN_CRIT "%s: target_cq %p\n", __func__, input->target_cq);
	fit_poll_cq(input->ctx, input->target_cq);
	kfree(input);
	//printk(KERN_CRIT "%s: kill ctx %p cq %p\n", __func__, (void *)input->ctx, (void *)input->target_cq);
	return 0;
}

int waiting_queue_handler(void *in)
{
	struct send_and_reply_format *new_request;
	int local_flag, last_ack, imm_data;
	struct lego_context *ctx = (struct lego_context *)in;
	//allow_signal(SIGKILL);
	
	//printk(KERN_CRIT "%s\n", __func__);
	while(1)
	{
		while(list_empty(&(request_list.list)))
		{
			schedule();
			//if(kthread_should_stop())
			//{
			//	printk(KERN_ALERT "Stop waiting_event_handler\n");
			//	return 0;
			//}
		}
		spin_lock(&wq_lock);
		new_request = list_entry(request_list.list.next, struct send_and_reply_format, list);

		spin_unlock(&wq_lock);
		if(new_request->src_id == ctx->node_id)
			local_flag = 1;
		else
			local_flag = 0;
		switch(new_request->type)
		{
			//printk(KERN_CRIT "%s got new req type %d\n", __func__, new_request->type);
			case MSG_DO_RC_POST_RECEIVE:
				//new_request->src_id keeps the connection_id (done by fit_poll_cq)
				fit_post_receives_message(ctx, new_request->src_id, new_request->length);
				break;
			case MSG_DO_ACK_INTERNAL:
				{
					//First do check again
					int offset = new_request->length;
					//struct app_reg_port *ptr = (struct app_reg_port *)new_request->msg;
					int target_node = (int) new_request->msg; //ptr->node;
					//int target_port = ptr->port;
					//printk(KERN_CRIT "%s: [generate ACK node-%d port-%d offset-%d]\n", __func__, target_node, target_port, offset);
#if 0					
					struct imm_ack_form ack_packet;
					uintptr_t tempaddr;
					//ptr->last_ack_index = offset;
					ack_packet.node_id= ctx->node_id;
					//ack_packet.designed_port = target_port;
					ack_packet.ack_offset = offset;
					tempaddr = fit_ib_reg_mr_addr(ctx, &ack_packet, sizeof(struct imm_ack_form));
					fit_send_message_sge(ctx, target_node, MSG_DO_ACK_REMOTE, (void *)tempaddr, sizeof(struct imm_ack_form), 0, 0, LOW_PRIORITY);
#endif
					imm_data = IMM_ACK | offset;
					//printk(KERN_CRIT "%s sending ack offset %d targetnode %d imm %x\n", __func__, offset, target_node, imm_data);
#ifdef CONFIG_SOCKET_O_IB					
					fit_send_message_with_rdma_write_with_imm_request(ctx, target_node * (NUM_PARALLEL_CONNECTION + 1), 
							0, 0, 0, 0, 0, offset, FIT_SEND_ACK_IMM_ONLY, NULL, FIT_KERNELSPACE_FLAG);
#else					
					fit_send_message_with_rdma_write_with_imm_request(ctx, target_node * NUM_PARALLEL_CONNECTION, 
							0, 0, 0, 0, 0, offset, FIT_SEND_ACK_IMM_ONLY, NULL, FIT_KERNELSPACE_FLAG);
#endif					
					break;
				}
			case MSG_DO_ACK_REMOTE:
				{
					last_ack = (int)new_request->msg; 
					//printk(KERN_CRIT "%s: [receive ACK node-%d offset-%d]\n", __func__, new_request->src_id, last_ack);
					ctx->remote_last_ack_index[new_request->src_id] = last_ack;
					break;
				}
			default:
				printk(KERN_ALERT "%s: receive weird event %d\n", __func__, new_request->type);
		}
		spin_lock(&wq_lock);
		list_del(&new_request->list);
		spin_unlock(&wq_lock);
		kfree(new_request);
		//kmem_cache_free(s_r_cache, new_request);
	}
}

void fit_setup_ibapi_header(uint32_t src_id, uint64_t inbox_addr, uint64_t inbox_semaphore, uint32_t length, int priority, int type, struct ibapi_header *output_header)
{
	output_header->src_id = src_id;
	output_header->inbox_addr = inbox_addr;
	output_header->inbox_semaphore = inbox_semaphore;
	output_header->length = length;
	output_header->priority = priority;
	output_header->type = type;
}

int fit_send_cq_poller(struct lego_context *ctx)
{
	int ne, i;
	struct ib_wc *wc;
	wc = kmalloc(sizeof(struct ib_wc)*128, GFP_KERNEL);
	while(1)
	{
		do{
			ne = ib_poll_cq(ctx->send_cq[0], 128, wc);
			if(ne < 0)
			{
				printk(KERN_ALERT "%s: poll send_cq polling failed at connection\n", __func__);
			}
			if(ne==0)
			{
				schedule();
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				printk(KERN_ALERT "%s: send request failed at id %llu as %d\n", __func__, wc[i].wr_id, wc[i].status);
			}
			//else
			//	printk(KERN_ALERT "%s: send request success at id %llu as %d\n", __func__, wc[i].wr_id, wc[i].status);
			*(int*)wc[i].wr_id = -wc[i].status;
		}
	}
	return 0;
}

int fit_send_request(struct lego_context *ctx, int connection_id, enum mode s_mode, struct fit_ibv_mr *input_mr, void *addr, int size, int offset, int userspace_flag)
{
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge;
	int ret;
	uintptr_t tempaddr;
	int poll_status = SEND_REPLY_WAIT;

//retry_send_request:
	memset(&wr, 0, sizeof(struct ib_send_wr));
	memset(&sge, 0, sizeof(struct ib_sge));

	wr.wr_id = (uint64_t)&poll_status;
	wr.opcode = (s_mode == M_WRITE) ? IB_WR_RDMA_WRITE : IB_WR_RDMA_READ;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_SIGNALED;

	wr.wr.rdma.remote_addr = (uintptr_t) (input_mr->addr+offset);
	wr.wr.rdma.rkey = input_mr->rkey;
	if(userspace_flag)
	{
		sge.addr = (uintptr_t)addr;
	}
	else
	{
		tempaddr = fit_ib_reg_mr_addr(ctx, addr, size);
		sge.addr = tempaddr;
	}
	sge.length = size;
	sge.lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	if(!ret)
	{
		fit_internal_poll_sendcq(ctx->send_cq[connection_id], connection_id, &poll_status);
	}
	else
	{
		printk(KERN_INFO "%s: send fail %d\n", __func__, connection_id);
	}
	return 0;
}

inline int fit_get_inbox_by_addr(struct lego_context *ctx, void *addr)
{
	int tar;
	spin_lock(&ctx->reply_ready_indicators_lock);

	tar = find_first_zero_bit(ctx->reply_ready_indicators_bitmap, IMM_NUM_OF_SEMAPHORE);
	while(tar==IMM_NUM_OF_SEMAPHORE)
	{
		schedule();
		tar = find_first_zero_bit(ctx->reply_ready_indicators_bitmap, IMM_NUM_OF_SEMAPHORE);
	}
	set_bit(tar, ctx->reply_ready_indicators_bitmap);	

	spin_unlock(&ctx->reply_ready_indicators_lock);
	ctx->reply_ready_indicators[tar] = addr;

	return tar;
}

int fit_send_reply_with_rdma_write_with_imm(struct lego_context *ctx, int target_node, void *addr, int size, void *ret_addr, int max_ret_size, int userspace_flag, int if_use_ret_phys_addr)
{
	int tar_offset_start;
	int connection_id;
	int inbox_id;
	int imm_data;
	int wait_send_reply_id = SEND_REPLY_WAIT;
	int real_size = size + sizeof(struct imm_message_metadata);
	void *remote_addr;
	uint32_t remote_rkey;
	struct fit_ibv_mr *remote_mr;
	struct imm_message_metadata output_header;
	int last_ack;
	
	if(size+sizeof(struct imm_message_metadata) > IMM_MAX_SIZE)
	{
		printk(KERN_CRIT "%s: message size %d + header is larger than max size %d\n", __func__, size, IMM_MAX_SIZE);
		return -1;
	}
	if(!addr)
	{
		printk(KERN_CRIT "%s: null input addr\n", __func__);
		return -2;
	}

	spin_lock(&ctx->remote_imm_offset_lock[target_node]);
	if(ctx->remote_rdma_ring_mrs_offset[target_node] + real_size >= RDMA_RING_SIZE)//If hits the end of ring, write start from 0 directly
		ctx->remote_rdma_ring_mrs_offset[target_node] = real_size;//Record the last point
	else
		ctx->remote_rdma_ring_mrs_offset[target_node] += real_size;
	tar_offset_start = ctx->remote_rdma_ring_mrs_offset[target_node] - real_size;//Trace back to the real starting point
	spin_unlock(&ctx->remote_imm_offset_lock[target_node]);

	//printk(KERN_CRIT "%s tar_offset_start %d real_size %d last_ack_index %d\n", 
	//		__func__, tar_offset_start, real_size, ctx->remote_last_ack_index[target_node]);
	//make sure does not over write than lastack
	while(1)
	{
		last_ack = ctx->remote_last_ack_index[target_node];
		if(tar_offset_start < last_ack && tar_offset_start + real_size > last_ack)
			schedule();
		else
			break;
	}

	remote_mr = &(ctx->remote_rdma_ring_mrs[target_node]);

	connection_id = fit_get_connection_by_atomic_number(ctx, target_node, LOW_PRIORITY);
	inbox_id = fit_get_inbox_by_addr(ctx, &wait_send_reply_id);
	
	imm_data = IMM_SEND_REPLY_SEND | tar_offset_start; 
	
	if (if_use_ret_phys_addr == 1)
		output_header.inbox_addr = fit_ib_reg_mr_addr_phys(ctx, ret_addr, max_ret_size);//This part need to be handled careful in the future
	else
		output_header.inbox_addr = fit_ib_reg_mr_addr(ctx, ret_addr, max_ret_size);//This part need to be handled careful in the future
	output_header.inbox_rkey = ctx->proc->rkey;
	output_header.inbox_semaphore = inbox_id;
	output_header.source_node_id = ctx->node_id;
	output_header.size = size;
	remote_addr = remote_mr->addr;
	remote_rkey = remote_mr->rkey;
	//printk(KERN_CRIT "%s: send imm-%x addr-%x rkey-%x oaddr-%x orkey-%x\n", __func__, imm_data, remote_addr, remote_rkey, output_header.inbox_addr, output_header.inbox_rkey);

#ifdef SCHEDULE_MODEL
	ctx->thread_waiting_for_reply[inbox_id] = get_current();
	set_current_state(TASK_INTERRUPTIBLE);
#endif
	fit_send_message_with_rdma_write_with_imm_request(ctx, connection_id, remote_rkey, 
			(uintptr_t)remote_addr, addr, size, tar_offset_start, imm_data, 
			FIT_SEND_MESSAGE_HEADER_AND_IMM, &output_header, FIT_KERNELSPACE_FLAG);

#ifdef SCHEDULE_MODEL
	schedule();
	set_current_state(TASK_RUNNING);
#endif

#ifdef CPURELAX_MODEL
	while(wait_send_reply_id==SEND_REPLY_WAIT)
	{
		cpu_relax();
	}
#endif

#ifdef ADAPTIVE_MODEL
	//If size is small, it should do busy wait here, or the waiting time is too long, it should jump to sleep queue
	if(size<=IMM_SEND_SLEEP_SIZE_THRESHOLD)
	{
		unsigned long j0,j1;
		j0 = jiffies;
		j1 = j0 + usecs_to_jiffies(IMM_SEND_SLEEP_TIME_THRESHOLD);
		while(wait_send_reply_id==SEND_REPLY_WAIT && time_before(jiffies, j1))
			//cpu_relax();
			schedule();
	}

	//do checking here, if the size is small and time is short, it should get wait_send_reply_id from the above if loop. Else do wait here.
	if(wait_send_reply_id==SEND_REPLY_WAIT)
	{
		while(wait_send_reply_id==SEND_REPLY_WAIT)
		{
			if(wait_event_interruptible_timeout(ctx->imm_inbox_block_queue[inbox_id], wait_send_reply_id!=SEND_REPLY_WAIT, msecs_to_jiffies(3000)))
				break;
		}
	}
#endif

	if(wait_send_reply_id < 0)
	{
		printk(KERN_CRIT "%s: [significant error] send-reply-imm fail with connection-%d inbox-%d status-%d\n", __func__, connection_id, inbox_id, wait_send_reply_id);
	}

	return wait_send_reply_id;
}

int fit_send_request_without_polling(struct lego_context *ctx, int connection_id, enum mode s_mode, struct fit_ibv_mr *input_mr, void *addr, int size, int offset, int wr_id)
{
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge;
	int ret;
	uintptr_t tempaddr;
	
	memset(&wr, 0, sizeof(struct ib_send_wr));
	memset(&sge, 0, sizeof(struct ib_sge));

	wr.wr_id = wr_id;
	wr.opcode = (s_mode == M_WRITE) ? IB_WR_RDMA_WRITE : IB_WR_RDMA_READ;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_SIGNALED;

	wr.wr.rdma.remote_addr = (uintptr_t) (input_mr->addr+offset);
	wr.wr.rdma.rkey = input_mr->rkey;
	tempaddr = fit_ib_reg_mr_addr(ctx, addr, size);
	sge.addr = tempaddr;
	sge.length = size;
	sge.lkey = ctx->proc->lkey;
	
	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	if(ret)
		printk("Error in [%s] ret:%d \n", __func__, ret);
	
	return 0;
}

int fit_send_request_polling_only(struct lego_context *ctx, int connection_id, int polling_num, struct ib_wc *wc)
{
	int ne, i;
	int cur_num = polling_num;
	spin_lock(&connection_lock[connection_id]);
	while(cur_num)
	{
		do{
			ne = ib_poll_cq(ctx->send_cq[connection_id], 12000, wc);
			if(ne < 0)
			{
				printk(KERN_ALERT "poll send_cq failed at connection %d\n", connection_id);
				return 1;
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				printk(KERN_ALERT "send request failed at connection %d as %d\n", connection_id, wc[i].status);
				return 2;
			}
		}
		cur_num = cur_num - ne;
	}
	spin_unlock(&connection_lock[connection_id]);
	return 0;
}

void fit_free_recv_buf(void *input_buf)
{
	kfree(input_buf);
	//kmem_cache_free(post_receive_cache, input_buf);
}

int fit_send_test(struct lego_context *ctx, int connection_id, int type, void *addr, int size, uint64_t inbox_addr, uint64_t inbox_semaphore, int priority)
{	
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge;
	int ret;
	int ne, i;
	struct ib_wc wc[2];

	printk(KERN_CRIT "%s conn %d addr %p size %d sendcq %p\n", __func__, connection_id, addr, size, ctx->send_cq[connection_id]);
	spin_lock(&connection_lock[connection_id]);

	memset(&wr, 0, sizeof(wr));

	sge.addr = (uintptr_t)fit_ib_reg_mr_addr(ctx, addr, size);
	sge.length = size;
	sge.lkey = ctx->proc->lkey;

	wr.wr_id = type;
	wr.opcode = IB_WR_SEND;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_SIGNALED;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	if(ret==0)
	{
		do{
			ne = ib_poll_cq(ctx->send_cq[connection_id], 1, wc);
			if(ne < 0)
			{
				printk(KERN_ALERT "poll send_cq failed at connection %d\n", connection_id);
				spin_unlock(&connection_lock[connection_id]);
				return 1;
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				printk(KERN_ALERT "send failed at connection %d as %d\n", connection_id, wc[i].status);
				spin_unlock(&connection_lock[connection_id]);
				return 2;
			}
		}
	}
	else
	{
		printk(KERN_INFO "%s send fail %d\n", __func__, connection_id);
	}
	spin_unlock(&connection_lock[connection_id]);
	return ret;
}

int fit_send_message_sge(struct lego_context *ctx, int connection_id, int type, void *addr, int size, uint64_t inbox_addr, uint64_t inbox_semaphore, int priority)
{	
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge[2];
	int ret;
	int ne, i;
	struct ib_wc wc[2];
	struct ibapi_header output_header;
	void *output_header_addr;

	printk(KERN_CRIT "%s conn %d addr %p size %d sendcq %p type %d\n", __func__, connection_id, addr, size, ctx->send_cq[connection_id], type);
	spin_lock(&connection_lock[connection_id]);

	memset(&wr, 0, sizeof(wr));
	memset(sge, 0, sizeof(struct ib_sge)*2);

	wr.wr_id = type;
	wr.opcode = IB_WR_SEND;
	wr.sg_list = sge;
	wr.num_sge = 2;
	wr.send_flags = IB_SEND_SIGNALED;

	fit_setup_ibapi_header(ctx->node_id, inbox_addr, inbox_semaphore, size, priority, type, &output_header);
	output_header_addr = (void *)fit_ib_reg_mr_addr(ctx, &output_header, sizeof(struct ibapi_header));
	sge[0].addr = (uintptr_t)output_header_addr;
	sge[0].length = sizeof(struct ibapi_header);
	sge[0].lkey = ctx->proc->lkey;
	sge[1].addr = (uintptr_t)fit_ib_reg_mr_addr(ctx, addr, size);
	sge[1].length = size;
	sge[1].lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	printk(KERN_CRIT "%s headeraddr %p %p bufaddr %p %#Lx lkey %d\n",
		__func__, &output_header, output_header_addr, addr, sge[1].addr, ctx->proc->lkey);
	if(ret==0)
	{
		do{
			ne = ib_poll_cq(ctx->send_cq[connection_id], 1, wc);
			if(ne < 0)
			{
				printk(KERN_ALERT "poll send_cq failed at connection %d\n", connection_id);
				return 1;
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				printk(KERN_ALERT "send failed at connection %d as %d\n", connection_id, wc[i].status);
				return 2;
			}
		}
	}
	else
	{
		printk(KERN_INFO "%s send fail %d\n", __func__, connection_id);
	}
	spin_unlock(&connection_lock[connection_id]);
	return ret;
}

int send_rdma_ring_mr_to_other_nodes(struct lego_context *ctx)
{
	int i;
	int connection_id;
	char *msg;
	int ret = 0;
	int size;

#ifdef CONFIG_SOCKET_O_IB
	msg = kmalloc(2 * sizeof(struct fit_ibv_mr), GFP_KERNEL);
	size = 2 * sizeof(struct fit_ibv_mr);
#else
	msg = kmalloc(sizeof(struct fit_ibv_mr), GFP_KERNEL);
	size = sizeof(struct fit_ibv_mr);
#endif
	for (i = 0; i < ctx->num_node; i++) {
		if (ctx->node_id == i)
			continue;
		memcpy(msg, &ctx->local_rdma_ring_mrs[i], sizeof(struct fit_ibv_mr)); 
#ifdef CONFIG_SOCKET_O_IB
		connection_id = (NUM_PARALLEL_CONNECTION + 1) * i;
		memcpy(msg + sizeof(struct fit_ibv_mr), &ctx->local_sock_rdma_ring_mrs[i], sizeof(struct fit_ibv_mr)); 
#else
		connection_id = NUM_PARALLEL_CONNECTION * i;
#endif

		pr_info("%s(): send ringmr addr %p lkey %x rkey %x conn %d node %d\n",
			__func__, ctx->local_rdma_ring_mrs[i].addr,
			ctx->local_rdma_ring_mrs[i].lkey, 
			ctx->local_rdma_ring_mrs[i].rkey, connection_id, i);
		//ret = fit_send_test(ctx, connection_id, MSG_SEND_RDMA_RING_MR, msg, sizeof(struct fit_ibv_mr), 0, 0, LOW_PRIORITY);
		ret = fit_send_message_sge(ctx, connection_id, MSG_SEND_RDMA_RING_MR, msg, sizeof(struct fit_ibv_mr), 0, 0, LOW_PRIORITY);
	}
	kfree(msg);

	return ret;
}

struct lego_context *fit_establish_conn(struct ib_device *ib_dev, int ib_port, int mynodeid)
{
	int     i;
        int             temp_ctx_number;
	struct lego_context *ctx;
	struct fit_ibv_mr *ret_mr;
	struct thread_pass_struct thread_pass_poll_cq;
	int num_connected_nodes = 0;
	num_recvd_rdma_ring_mrs = 0;

        temp_ctx_number = atomic_inc_return(&Connected_FIT_Num);
        if(temp_ctx_number>=MAX_FIT_NUM)
        {
                printk(KERN_CRIT "%s Error: already meet the upper bound of connected FIT %d\n", __func__, temp_ctx_number);
                atomic_dec(&Connected_FIT_Num);
                return 0;
        }
	
	pr_info("***  Start establish connection (mynodeid: %d)\n", mynodeid);

	init_global_lid_qpn();
	print_gloabl_lid();

	ctx = fit_init_interface(ib_port, ib_dev, mynodeid);
	if(!ctx)
	{
		printk(KERN_ALERT "%s: ctx %p fail to init_interface \n", __func__, (void *)ctx);
		return 0;	
	}
        
        Connected_Ctx[temp_ctx_number-1] = ctx;

	for(i=0;i<MAX_CONNECTION;i++)
	{
		spin_lock_init(&connection_lock[i]);
	}

#ifdef CONFIG_SOCKET_O_IB
	for (i = 0; i < MAX_NODE; i++) {
		spin_lock_init(&sock_qp_lock[i]);
	}
#endif

	//Initialize waiting_queue/request list related items
	spin_lock_init(&wq_lock);
	INIT_LIST_HEAD(&(request_list.list));

	//Initialize multicast spin_lock
	spin_lock_init(&multicast_lock);

	//Start handling completion cq
	thread_pass_poll_cq.ctx = ctx;
	thread_pass_poll_cq.target_cq = ctx->cq[0];
	kthread_run(fit_poll_cq_pass, &thread_pass_poll_cq, "recvpollcq");
	//wake_up_process(thread);
	printk(KERN_CRIT "%s created poll cq thread\n", __func__);
	
	kthread_run(waiting_queue_handler, ctx, "wq_handler");
	printk(KERN_CRIT "%s created wait queue thread\n", __func__);

#ifdef SEPARATE_SEND_POLL_THREAD
	thread = kthread_create((void *)fit_send_cq_poller, ctx, "separate_poll_send");
	if(IS_ERR(thread))
	{
		printk(KERN_ALERT "fail to do send-cq poller\n");
		return 0;
	}
	wake_up_process(thread);
#endif

	/*
	 * Allocate and register local RDMA-IMM rings for all nodes
	 */
	ctx->local_rdma_recv_rings = kmalloc(MAX_NODE * sizeof(void *), GFP_KERNEL);
	ctx->local_rdma_ring_mrs = (struct fit_ibv_mr *)kmalloc(MAX_NODE * sizeof(struct fit_ibv_mr), GFP_KERNEL);
	for(i=0; i<MAX_NODE; i++)
	{
		ctx->local_rdma_recv_rings[i] = fit_alloc_memory_for_mr(IMM_PORT_CACHE_SIZE);
		ret_mr = fit_ib_reg_mr(ctx, ctx->local_rdma_recv_rings[i], IMM_RING_SIZE,
				IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ);
		memcpy(&ctx->local_rdma_ring_mrs[i], ret_mr, sizeof(struct fit_ibv_mr));
		printk(KERN_CRIT "allocated local recv mr for node %d addr %p %p lkey %d rkey %d",
				i, ctx->local_rdma_recv_rings[i], ret_mr->addr, ret_mr->lkey, ret_mr->rkey);
	}
	/* array to store rdma ring mr for all remote nodes */
	ctx->remote_rdma_ring_mrs = (struct fit_ibv_mr *)kmalloc(MAX_NODE * sizeof(struct fit_ibv_mr), GFP_KERNEL);
	ctx->remote_rdma_ring_mrs_offset = (int *)kzalloc(MAX_NODE * sizeof(int), GFP_KERNEL);
	ctx->remote_last_ack_index = (int *)kzalloc(MAX_NODE * sizeof(int), GFP_KERNEL);
	ctx->local_last_ack_index = (int *)kzalloc(MAX_NODE * sizeof(int), GFP_KERNEL);
	ctx->local_last_ack_index_lock = (spinlock_t *)kmalloc(MAX_NODE * sizeof(spinlock_t), GFP_KERNEL);
	ctx->remote_imm_offset_lock = (spinlock_t *)kmalloc(MAX_NODE * sizeof(spinlock_t), GFP_KERNEL); 
	for(i=0; i<MAX_NODE; i++) {
		spin_lock_init(&ctx->remote_imm_offset_lock[i]);
		spin_lock_init(&ctx->local_last_ack_index_lock[i]);
	}

#ifdef CONFIG_SOCKET_O_IB
	/*
	 * Allocate and register local RDMA-IMM rings for socket
	 */
	ctx->local_sock_rdma_recv_rings = kmalloc(MAX_NODE * sizeof(void *), GFP_KERNEL);
	ctx->local_sock_rdma_ring_mrs = (struct fit_ibv_mr *)kmalloc(MAX_NODE * sizeof(struct fit_ibv_mr), GFP_KERNEL);
	for(i = 0; i < MAX_NODE; i++)
	{
		ctx->local_sock_rdma_recv_rings[i] = fit_alloc_memory_for_mr(SOCK_PERNODE_RECV_MR_SIZE);
		ret_mr = fit_ib_reg_mr(ctx, ctx->local_sock_rdma_recv_rings[i], SOCK_PERNODE_RECV_MR_SIZE,
				IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ);
		memcpy(&ctx->local_sock_rdma_ring_mrs[i], ret_mr, sizeof(struct fit_ibv_mr));
		//printk(KERN_CRIT "allocated local recv mr for node %d addr %p %p lkey %d rkey %d",
		//		i, ctx->local_rdma_recv_rings[i], ret_mr->addr, ret_mr->lkey, ret_mr->rkey);
	}
	/* array to store rdma ring mr for socket */
	ctx->remote_sock_rdma_ring_mrs = (struct fit_ibv_mr *)kmalloc(MAX_NODE * sizeof(struct fit_ibv_mr), GFP_KERNEL);
	ctx->remote_sock_rdma_ring_mrs_offset = (int *)kzalloc(MAX_NODE * sizeof(int), GFP_KERNEL);
	ctx->remote_sock_last_ack_index = (int *)kzalloc(MAX_NODE * sizeof(int), GFP_KERNEL);
	ctx->local_sock_last_ack_index = (int *)kzalloc(MAX_NODE * sizeof(int), GFP_KERNEL);
	ctx->local_sock_last_ack_index_lock = (spinlock_t *)kmalloc(MAX_NODE * sizeof(spinlock_t), GFP_KERNEL);
	ctx->remote_sock_imm_offset_lock = (spinlock_t *)kmalloc(MAX_NODE * sizeof(spinlock_t), GFP_KERNEL); 
	for(i=0; i<MAX_NODE; i++) {
		spin_lock_init(&ctx->remote_sock_imm_offset_lock[i]);
		spin_lock_init(&ctx->local_sock_last_ack_index_lock[i]);
	}
#endif

	printk(KERN_CRIT "[%s] node: %d allocated local rdma buffers, about to connect qps\n", __func__, mynodeid);
	ctx->node_id = mynodeid;
	for (i = 0; i < mynodeid; i++) {
		fit_add_newnode(ctx, i, mynodeid);
		num_connected_nodes++;
	}

	//if (num_connected_nodes == mynodeid - 1) {
		for (i = mynodeid + 1; i < MAX_NODE; i++) {
			fit_add_newnode(ctx, i, mynodeid);
			num_connected_nodes ++;
		}
	//}
	printk(KERN_CRIT "%s all connections completed\n", __func__);
	//schedule();

	for (i = 0; i < 30000; i++) {
		udelay(1000);
	}

	printk(KERN_CRIT "now sending mr info\n");
	//if (ctx->node_id == 0)
		send_rdma_ring_mr_to_other_nodes(ctx);
	//else
	//	fit_poll_cq_pass(&thread_pass_poll_cq);
	printk(KERN_CRIT "%s sent rdma ring mrs\n", __func__);

	//schedule();

	while (num_recvd_rdma_ring_mrs < ctx->num_node - 1)
		//cpu_relax();
		schedule();

	printk(KERN_ALERT "%s: return before establish connection with NODE_ID: %d\n", __func__, ctx->node_id);

	return ctx;
}

int fit_cleanup_module(void)
{
	printk(KERN_INFO "Ready to remove module\n");
	return 0;
}

int fit_internal_init(void)
{
        Connected_Ctx = (struct lego_context **)kmalloc(sizeof(struct lego_context*)*MAX_FIT_NUM, GFP_KERNEL);
        atomic_set(&Connected_FIT_Num, 0);
	printk(KERN_CRIT "insmod fit_internal module\n");
	return 0;
}

int fit_internal_cleanup(void)
{
	printk(KERN_CRIT "rmmod fit_internal module\n");
	return 0;
}
