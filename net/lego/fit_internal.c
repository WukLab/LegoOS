/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/init.h>
#include <lego/mm.h>
#include <lego/net.h>
//#include <lego/kthread.h>
#include <lego/workqueue.h>
//#include <lego/semaphore.h>
//#include <lego/completion.h>
#include <lego/list.h>
#include <lego/string.h>
#include <lego/jiffies.h>
#include <lego/pci.h>
#include <lego/delay.h>
#include <lego/slab.h>
#include <lego/time.h>
#include <lego/kernel.h>
#include <rdma/ib_verbs.h>

#include "fit_internal.h"

enum ib_mtu client_mtu_to_enum(int mtu)
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
struct client_data full_connect_data[MAX_CONNECTION];
struct client_data my_QPset[MAX_CONNECTION];
int                     ib_port = 1;
//static struct task_struct **thread_poll_cq, *thread_handler;

ppc **Connected_Ctx;
atomic_t Connected_FIT_Num;

int num_recvd_rdma_ring_mrs;

spinlock_t wq_lock;

spinlock_t connection_lock[MAX_CONNECTION];
spinlock_t connection_lock_pedal[MAX_CONNECTION];
spinlock_t multicast_lock; //only one multicast can be executed at a single time

//struct send_and_reply_format request_list;

#if 0
//LOCK related
#define HASH_TABLE_SIZE_BIT 16
DEFINE_HASHTABLE(LOCK_QUEUE_HASHTABLE, HASH_TABLE_SIZE_BIT);
spinlock_t LOCK_QUEUE_HASHTABLE_LOCK[1<<HASH_TABLE_SIZE_BIT];
#endif

long long int Internal_Stat_Sum=0;
int Internal_Stat_Count=0;

int client_find_cq(ppc *ctx, struct ib_cq *tar_cq)
{
	int i;
	if(ctx->cqUD == tar_cq)
	{
		return NUM_POLLING_THREADS;
	}
	for(i=0;i<NUM_POLLING_THREADS;i++)
	{
		if(ctx->cq[i]==tar_cq)
			return i;
	}

	return -1;
}

struct pingpong_context *client_init_ctx(int size, int rx_depth, int port, struct ib_device *ib_dev)
{
	int i;
	int num_connections = MAX_CONNECTION;
	ppc *ctx;

	printk(KERN_CRIT "%s\n", __func__);
	ctx = (struct pingpong_context*)kzalloc(sizeof(struct pingpong_context), GFP_KERNEL);
	if(!ctx)
	{
		printk(KERN_ALERT "FAIL to initialize ctx in client_init_ctx\n");
		return NULL;
	}
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

	//ctx->send_cq[0] = ib_create_cq((struct ib_device *)ctx->context, NULL, NULL, NULL, rx_depth+1, 0);
	for(i=0;i<num_connections;i++)
	{
		ctx->send_state[i] = SS_INIT;
		ctx->recv_state[i] = RS_INIT;

		ctx->send_cq[i] = ib_create_cq((struct ib_device *)ctx->context, NULL, NULL, NULL, rx_depth+1, 0);
		//ctx->send_cq[i] = ctx->send_cq[0];
		struct ib_qp_attr attr;
		struct ib_qp_init_attr init_attr = {
			.send_cq = ctx->send_cq[i],//ctx->cq
			.recv_cq = ctx->cq[i%NUM_POLLING_THREADS],
			.cap = {
				.max_send_wr = rx_depth + 2,
				//.max_send_wr = 12000,
				.max_recv_wr = rx_depth,
				.max_send_sge = 16,
				.max_recv_sge = 16
			},
			.qp_type = IB_QPT_RC,
			.sq_sig_type = IB_SIGNAL_REQ_WR
		};

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

		struct ib_qp_attr attr1 = {
			.qp_state = IB_QPS_INIT,
			.pkey_index = 0,
			.port_num = port,
			.qp_access_flags = IB_ACCESS_REMOTE_WRITE|IB_ACCESS_REMOTE_READ|IB_ACCESS_LOCAL_WRITE|IB_ACCESS_REMOTE_ATOMIC,
			.path_mtu = IB_MTU_4096,
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
	}

	//Do IMM local ring setup (imm-send-reply)
	ctx->imm_inbox_semaphore = (void **)kmalloc(sizeof(void*)*IMM_NUM_OF_SEMAPHORE, GFP_KERNEL);
	ctx->imm_inbox_semaphore_bitmap = kzalloc(sizeof(unsigned long) * BITS_TO_LONGS(IMM_NUM_OF_SEMAPHORE), GFP_KERNEL);
	spin_lock_init(&ctx->imm_inbox_semaphore_lock);

	for(i=0;i<IMM_MAX_PORT;i++)
	{
		INIT_LIST_HEAD(&(ctx->imm_waitqueue_perport[i].list));
		spin_lock_init(&ctx->imm_waitqueue_perport_lock[i]);
		ctx->imm_perport_reg_num[i]=-1;
	}
	
#ifdef ADAPTIVE_MODEL
	ctx->imm_inbox_block_queue = (wait_queue_head_t*)kmalloc((IMM_NUM_OF_SEMAPHORE)*sizeof(wait_queue_head_t), GFP_KERNEL);
	for(i=0;i<IMM_NUM_OF_SEMAPHORE;i++)
	        init_waitqueue_head(&ctx->imm_inbox_block_queue[i]);
#endif
#ifdef SCHEDULE_MODEL
	ctx->imm_inbox_semaphore_task = (struct task_struct **)kzalloc(sizeof(struct task_struct*)*IMM_NUM_OF_SEMAPHORE, GFP_KERNEL);
#endif
	
	#if 0
	//Lock related
	atomic_set(&ctx->lock_num, 0);
	ctx->lock_data = kzalloc(sizeof(struct fit_lock_form)*FIT_MAX_LOCK_NUM, GFP_KERNEL);
	#endif
	return ctx;
}

ppc *client_init_interface(int ib_port, struct ib_device *ib_dev)
{
	int	size = 4096;
	int	rx_depth = RECV_DEPTH;
	int	ret;
	ppc *ctx;
	mtu = IB_MTU_4096;
	sl = 0;

	page_size = PAGE_SIZE;
	rcnt = 0;
	scnt = 0;
	ctx = client_init_ctx(size,rx_depth,ib_port, ib_dev);
	if(!ctx)
	{
		printk(KERN_ALERT "Fail to do client_init_ctx\n");
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

	//test_printk(KERN_ALERT "I am here before return client_init_interface\n");
	return ctx;

}

uintptr_t client_ib_reg_mr_phys_addr(ppc *ctx, void *addr, size_t length)
{
	struct ib_device *ibd = (struct ib_device*)ctx->context;
	return (uintptr_t)phys_to_dma(ibd->dma_device, (phys_addr_t)addr);
}

int pr_test=0;
struct ib_mr *proc_test;

struct client_ibv_mr *client_ib_reg_mr(ppc *ctx, void *addr, size_t length, enum ib_access_flags access)
{
	struct client_ibv_mr *ret;
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

	ret = (struct client_ibv_mr *)kmalloc(sizeof(struct client_ibv_mr), GFP_KERNEL);
	
	#ifdef PHYSICAL_ALLOCATION
	ret->addr = (void *)client_ib_reg_mr_phys_addr(ctx, (void *)virt_to_phys(addr), length);
	#else
	ret->addr = (void *)ib_dma_map_single((struct ib_device *)ctx->context, addr, length, DMA_BIDIRECTIONAL); 
	#endif
	
	ret->length = length;
	ret->lkey = proc->lkey;
	ret->rkey = proc->rkey;
	ret->node_id = ctx->node_id;
	printk(KERN_CRIT "%s length %d addr:%x lkey:%d rkey:%d\n", __func__, (int) length, (unsigned int)ret->addr, ret->lkey, ret->rkey);
	return ret;
}

inline uintptr_t client_ib_reg_mr_addr(ppc *ctx, void *addr, size_t length)
{
	#ifdef PHYSICAL_ALLOCATION
	return client_ib_reg_mr_phys_addr(ctx, (void *)virt_to_phys(addr), length);
	#endif
	#ifndef PHYSICAL_ALLOCATION
	return (uintptr_t)ib_dma_map_single((struct ib_device *)ctx->context, addr, length, DMA_BIDIRECTIONAL); 
	#endif
}

void client_ib_dereg_mr_addr(ppc *ctx, void *addr, size_t length)
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

int client_post_receives_message(ppc *ctx, int connection_id, int depth)
{
	int i;

	for(i=0;i<depth;i++)
	{
		struct ib_recv_wr wr, *bad_wr = NULL;
		wr.wr_id = i + (connection_id << CONNECTION_ID_PUSH_BITS_BASED_ON_RECV_DEPTH);
		wr.next = NULL;
		wr.sg_list = NULL;
		wr.num_sge = 0;
		ib_post_recv(ctx->qp[connection_id], &wr, &bad_wr);
	}

	//printk(KERN_CRIT "%s: FIT_STAT post-receive %d bytes, %lld ns\n", __func__, POST_RECEIVE_CACHE_SIZE, client_internal_stat(0, FIT_STAT_CLEAR));
	return depth;
}

int client_post_receives_message_with_buffer(ppc *ctx, int connection_id, int depth)
{
	int i;
	char *buf, *header;
	uintptr_t header_addr;
	struct ibapi_post_receive_intermediate_struct *p_r_i_struct;
	uintptr_t addr;
	int size = 4096; //sizeof(struct client_ibv_mr);
	int ret;
	struct page *pp;
        pp = alloc_pages(GFP_KERNEL, 1);

	printk(KERN_CRIT "%s conn %d post %d buffers\n", __func__, connection_id, depth);
	for(i=0;i<depth;i++)
	{
		struct ib_sge sge[1];

        	buf = (char *)page_address(pp);
		//buf = kmalloc(sizeof(struct client_ibv_mr), GFP_KERNEL);
		addr = client_ib_reg_mr_addr(ctx, buf, size);
/*
		header = kmalloc(sizeof(struct ibapi_header), GFP_KERNEL);
		header_addr = client_ib_reg_mr_addr(ctx, header, sizeof(struct ibapi_header));
		p_r_i_struct = (struct ibapi_post_receive_intermediate_struct *)kmalloc(sizeof(struct ibapi_post_receive_intermediate_struct), GFP_KERNEL);
		p_r_i_struct->header = (uintptr_t)header_addr;
		p_r_i_struct->msg = (uintptr_t)addr;

		sge[0].addr = (uintptr_t)header_addr;
		sge[0].length = sizeof(struct ibapi_header);
		sge[0].lkey = ctx->proc->lkey;
*/
		sge[0].addr = (uintptr_t)addr;
		sge[0].length = size;
		sge[0].lkey = ctx->proc->lkey;

		struct ib_recv_wr wr, *bad_wr = NULL;
		wr.wr_id = size; //(uint64_t)p_r_i_struct;
		wr.next = NULL;
		wr.sg_list = sge;
		wr.num_sge = 1;
		ret = ib_post_recv(ctx->qp[connection_id], &wr, &bad_wr);
		if (ret) {
			printk(KERN_CRIT "ERROR: %s post recv error %d conn %d i %d\n", 
				__func__, ret, connection_id, i);
		}
		printk(KERN_CRIT "%s header %p header_addr %p buf %p addr %p lkey %d\n", 
				__func__, header, header_addr, buf, addr, ctx->proc->lkey);
	}

	//printk(KERN_CRIT "%s: FIT_STAT post-receive %d bytes, %lld ns\n", __func__, POST_RECEIVE_CACHE_SIZE, client_internal_stat(0, FIT_STAT_CLEAR));
	return depth;
}

int client_connect_ctx(ppc *ctx, int connection_id, int port, enum ib_mtu mtu, int sl, int destlid, int destqpn)
{
	struct ib_qp_attr attr = {
		.qp_state	= IB_QPS_RTR,
		.path_mtu	= mtu,
		.dest_qp_num	= destqpn,
		.rq_psn		= 1,
		.max_dest_rd_atomic	= 10,
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
	attr.timeout	= 14;
	attr.retry_cnt	= 7;
	attr.rnr_retry	= 7;
	attr.sq_psn	= 1;
	attr.max_rd_atomic = 10; //was 1
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
	return 0;
}

int *global_lid;

/* 
 * Statically setting LIDs and QPNs now
 * since we don't have socket working
 */
void init_global_lid_qpn(void)
{
	global_lid = (int *)kmalloc(MAX_NODE * sizeof(int), GFP_KERNEL);
	global_lid[0] = 7;
	global_lid[1] = 5;
}

int get_global_qpn(int mynodeid, int remnodeid, int conn)
{
	int first_qpn = 72;
	int ret;

	if (remnodeid > mynodeid)
		ret = mynodeid * NUM_PARALLEL_CONNECTION + conn;
	else
		ret = (remnodeid + mynodeid - 1) * NUM_PARALLEL_CONNECTION + conn;

	return ret + first_qpn;
}

int init_global_connt = 0;

int client_add_newnode(ppc *ctx, int rem_node_id)
{
	int i;
	int ret;
	int cur_connection;
	int global_qpn;

	for (i = 0; i < NUM_PARALLEL_CONNECTION; i++) {
		cur_connection = init_global_connt; //(rem_node_id*ctx->num_parallel_connection)+atomic_read(&ctx->num_alive_connection[rem_node_id]);
		global_qpn = get_global_qpn(ctx->node_id, rem_node_id, i);
		printk(KERN_ALERT "%s: cur connection %d mynode %d remnode %d remotelid %d remoteqpn %d\n", 
				__func__, cur_connection, ctx->node_id, rem_node_id, global_lid[rem_node_id], global_qpn);
retry:
		ret = client_connect_ctx(ctx, cur_connection, ib_port, mtu, sl, global_lid[rem_node_id], global_qpn);
		if(ret)
		{
			printk("fail to connect to node %d conn %d\n", rem_node_id, i);
			goto retry;
		}

		/* post receive buffers to get remote ring mrs, always through first conn */
		//if (i == 0)
			client_post_receives_message_with_buffer(ctx, cur_connection, ctx->num_node - 1);

		/* post receive buffers for IMM */
		client_post_receives_message(ctx, cur_connection, ctx->rx_depth);

		atomic_inc(&ctx->num_alive_connection[rem_node_id]);
		atomic_inc(&ctx->alive_connection);
		if(atomic_read(&ctx->num_alive_connection[rem_node_id]) == NUM_PARALLEL_CONNECTION)
		{
			atomic_inc(&ctx->num_alive_nodes);
			//printk(KERN_CRIT "%s: complete %d connection %d\n", __func__, NUM_PARALLEL_CONNECTION, rem_dest.node_id);
		}

		init_global_connt++;
	}

	printk(KERN_ALERT "successfully connect to node %d\n", rem_node_id);
	return 0;
}

inline int client_find_qp_id_by_qpnum(ppc *ctx, uint32_t qp_num)
{
	int i;
	for(i=0;i<ctx->num_connections;i++)
	{
		if(ctx->qp[i]->qp_num==qp_num)
			return i;
	}
	return -1;
}
inline int client_find_node_id_by_qpnum(ppc *ctx, uint32_t qp_num)
{
	int tmp = client_find_qp_id_by_qpnum(ctx, qp_num);
	if(tmp>=0)
	{
		return tmp/NUM_PARALLEL_CONNECTION;
	}
	return -1;
}

int client_internal_poll_sendcq(struct ib_cq *tar_cq, int connection_id, int *check)
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
	do{
		ne = ib_poll_cq(tar_cq, 1, wc);
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
		else
			break;
	}
	return 0;
#endif
}

int client_send_message_with_rdma_write_with_imm_request(ppc *ctx, int connection_id, uint32_t input_mr_rkey, 
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

retry_send_imm_request:
	memset(&wr, 0, sizeof(struct ib_send_wr));
	memset(&sge, 0, sizeof(struct ib_sge));
	
	wr.sg_list = sge;
	wr.wr.rdma.remote_addr = (uintptr_t) (input_mr_addr+offset);
	wr.wr.rdma.rkey = input_mr_rkey;

	if(s_mode == FIT_SEND_MESSAGE_HEADER_AND_IMM)
	{
		wr.wr_id = (uint64_t)ctx->imm_inbox_semaphore[header->inbox_semaphore];//get the real wait_send_reply_id address from inbox information
		wr.send_flags = IB_SEND_SIGNALED;
		wr.num_sge = 2;
		wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;

		temp_header_addr = client_ib_reg_mr_addr(ctx, header, sizeof(struct imm_message_metadata));
		wr.ex.imm_data = imm;
		
		sge[0].addr = temp_header_addr;
		sge[0].length = sizeof(struct imm_message_metadata);
		sge[0].lkey = ctx->proc->lkey;
		if(userspace_flag == FIT_KERNELSPACE_FLAG)
		{
			temp_addr = client_ib_reg_mr_addr(ctx, addr, size);
			sge[1].addr = temp_addr;
		}
		else
		{
			sge[1].addr = (uintptr_t)addr;
		}
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
		if(userspace_flag == FIT_KERNELSPACE_FLAG)
		{
			temp_addr = client_ib_reg_mr_addr(ctx, addr, size);
			sge[0].addr = temp_addr;
		}
		else
		{
			sge[0].addr = (uintptr_t)addr;
		}
		sge[0].length = size;
		sge[0].lkey = ctx->proc->lkey;
	}
	else
	{
		printk(KERN_CRIT "%s: wrong mode %d - testing function\n", __func__, s_mode);
		return -1;
	}

	spin_lock(&connection_lock[connection_id]);
	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	
	if(!ret)
	{
		client_internal_poll_sendcq(ctx->send_cq[connection_id], connection_id, &poll_status);
	}
	else
	{
		printk(KERN_INFO "%s: send fail %d ret %d\n", __func__, connection_id, ret);
	}
	spin_unlock(&connection_lock[connection_id]);

	return 0;
}

inline int client_get_connection_by_atomic_number(ppc *ctx, int target_node, int priority)
{
	return atomic_inc_return(&ctx->atomic_request_num[target_node]) % (atomic_read(&ctx->num_alive_connection[target_node])) 
			+ NUM_PARALLEL_CONNECTION * target_node;
}

/*
 * LEGO
 * reply msg
 * when this function returns, reply msg is delivered
 * and app can delete reply buffer
 */
int client_reply_message(ppc *ctx, void *addr, int size, uintptr_t descriptor, int userspace_flag)
{
	struct imm_message_metadata *tmp = (struct imm_message_metadata *)descriptor;
	int re_connection_id = client_get_connection_by_atomic_number(ctx, tmp->source_node_id, LOW_PRIORITY);
	unsigned long phys_addr;

	client_send_message_with_rdma_write_with_imm_request(ctx, re_connection_id, 
			tmp->inbox_rkey, tmp->inbox_addr, addr, size, 0, 
			tmp->inbox_semaphore | IMM_SEND_REPLY_RECV, FIT_SEND_MESSAGE_IMM_ONLY, NULL, FIT_KERNELSPACE_FLAG);

	kfree(tmp);
	//kmem_cache_free(imm_message_metadata_cache, tmp);
	return 0;
}

// XXX
int client_query_port(ppc *ctx, int target_node, int designed_port, int requery_flag)
{	
	uintptr_t tempaddr;
	int priority = LOW_PRIORITY;
	int wait_send_reply_id;
	struct ask_mr_reply_form reply_mr_form;
	int dummy;

	wait_send_reply_id = SEND_REPLY_WAIT;
	tempaddr = client_ib_reg_mr_addr(ctx, &dummy, sizeof(int));
//	client_send_message_sge_UD(ctx, target_node, MSG_QUERY_PORT_1, (void *)tempaddr, sizeof(int), 
//			(uint64_t)&reply_mr_form, (uint64_t)&wait_send_reply_id, priority);
	while(wait_send_reply_id==SEND_REPLY_WAIT)
		cpu_relax();
	if(reply_mr_form.op_code == MR_ASK_SUCCESS)
	{
		memcpy(&ctx->remote_rdma_ring_mrs[target_node], &reply_mr_form.reply_mr, sizeof(struct client_ibv_mr));
		printk(KERN_CRIT "%s: SUCCESS node %d remote addr %p remote rkey %d\n", 
				__func__, target_node, ctx->remote_rdma_ring_mrs[target_node].addr, ctx->remote_rdma_ring_mrs[target_node].rkey);
		return reply_mr_form.op_code;
	}

	printk(KERN_CRIT "%s: FAIL\n", __func__);
	return reply_mr_form.op_code;
}

void *client_alloc_memory_for_mr(unsigned int length)
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
int client_poll_cq(ppc *ctx, struct ib_cq *target_cq)
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
#ifdef NOTIFY_MODEL
	int test_result=0;
#endif
	//set_current_state(TASK_INTERRUPTIBLE);

	printk(KERN_CRIT "%s\n", __func__);
	while(1)
	{
		do{
			//set_current_state(TASK_RUNNING);
			ne = ib_poll_cq(target_cq, NUM_PARALLEL_CONNECTION, wc);
			if(ne < 0)
			{
				printk(KERN_ALERT "poll CQ failed %d\n", ne);
				return 1;
			}
			if(ne==0)
			{
				schedule();
				//cpu_relax();
				//set_current_state(TASK_INTERRUPTIBLE);
				//if(kthread_should_stop())
				//{
				//	printk(KERN_ALERT "Stop cq and return\n");
				//	return 0;
				//}
			}
			//msleep(1);
		}while(ne < 1);

		for(i=0;i<ne;++i)
		{
			printk(KERN_CRIT "%s got one recv cq status %d opcode %d\n",
					__func__, wc[i].status, wc[i].opcode);
			if(wc[i].status != IB_WC_SUCCESS)
			{
				printk(KERN_ALERT "%s: failed status (%d) for wr_id %d\n", __func__, wc[i].status, (int) wc[i].wr_id);
			}

			if((int) wc[i].opcode == IB_WC_RECV)
			{
				printk(KERN_CRIT "%s received IB_WC_RECV size %d\n", wc[i].wr_id);
			/*
				struct ibapi_post_receive_intermediate_struct *p_r_i_struct = (struct ibapi_post_receive_intermediate_struct*)wc[i].wr_id;
				struct ibapi_header temp_header;

				memcpy(&temp_header, (void *)p_r_i_struct->header + 40, sizeof(struct ibapi_header));
				addr = (char *)p_r_i_struct->msg;
				type = temp_header.type;

				if (type == MSG_SEND_RDMA_RING_MR) {
					memcpy(&ctx->remote_rdma_ring_mrs[temp_header.src_id], addr, sizeof(struct client_ibv_mr));
					num_recvd_rdma_ring_mrs++;
					printk(KERN_CRIT "node %d remote addr %p remote rkey %d\n", 
							temp_header.src_id, ctx->remote_rdma_ring_mrs[temp_header.src_id].addr, 
							ctx->remote_rdma_ring_mrs[temp_header.src_id].rkey);
				}
			*/
			}
			else if((int) wc[i].opcode == IB_WC_RECV_RDMA_WITH_IMM)
			{
				node_id = GET_NODE_ID_FROM_POST_RECEIVE_ID(wc[i].wr_id);
				if(wc[i].wc_flags&&IB_WC_WITH_IMM)
				{
					if(wc[i].ex.imm_data & IMM_SEND_REPLY_SEND && wc[i].ex.imm_data & IMM_SEND_REPLY_RECV)//opcode
					{
						//printk(KERN_CRIT "%s: opcode from node %d\n", __func__, node_id);
						semaphore = wc[i].ex.imm_data & IMM_GET_SEMAPHORE;
						opcode = IMM_GET_OPCODE_NUMBER(wc[i].ex.imm_data);
						//printk(KERN_CRIT "%s: case 1 semaphore-%d\n", __func__, semaphore);
						*(int *)(ctx->imm_inbox_semaphore[semaphore]) = -(opcode);
						ctx->imm_inbox_semaphore[semaphore] = NULL;
						clear_bit(semaphore, ctx->imm_inbox_semaphore_bitmap);
					}
					else if(wc[i].ex.imm_data & IMM_SEND_REPLY_SEND) // only send
					{
						// = (struct imm_message_metadata *)kmalloc(sizeof(struct imm_message_metadata), GFP_KERNEL);
						offset = wc[i].ex.imm_data & IMM_GET_OFFSET; 
						port = IMM_GET_PORT_NUMBER(wc[i].ex.imm_data);

						if(ctx->imm_perport_reg_num[port]<0)
						{
							printk(KERN_CRIT "%s: from node %d access to port %d is banned. This should not happen since sender should not be able to send this request out\n", __func__, node_id, port);
						}
						//printk(KERN_CRIT "%s: from node %d access to port %d imm-%x\n", __func__, node_id, port, wc[i].ex.imm_data);
						//memcpy(descriptor, ctx->local_rdma_ring_mrs[node_id] + offset, sizeof(struct imm_message_metadata));
						descriptor = (struct imm_message_metadata *)(ctx->local_rdma_recv_rings[node_id] + offset);
						// XXX call LEGO handler	
						ctx->send_reply_rdma_imm_handler(node_id, 
								ctx->local_rdma_recv_rings[node_id] + offset + sizeof(struct imm_message_metadata),
								descriptor->size, descriptor->inbox_addr, descriptor->inbox_rkey, descriptor->inbox_semaphore);
					}
					else //handle reply
					{
						length = wc[i].byte_len;
						semaphore = wc[i].ex.imm_data & IMM_GET_SEMAPHORE;
						//printk(KERN_CRIT "%s: case 2 semaphore-%d len-%d\n", __func__, semaphore, wc[i].byte_len);
						//*(int *)(ctx->imm_inbox_semaphore[semaphore]) = wc[i].byte_len;
						memcpy((void *)ctx->imm_inbox_semaphore[semaphore], &length, sizeof(int));

						#ifdef ADAPTIVE_MODEL
                	        		wake_up_interruptible(&ctx->imm_inbox_block_queue[semaphore]);//Wakeup waiting queue
						#endif
						#ifdef SCHEDULE_MODEL
						wake_up_process(ctx->imm_inbox_semaphore_task[semaphore]);
						ctx->imm_inbox_semaphore_task[semaphore]=NULL;
						#endif

						ctx->imm_inbox_semaphore[semaphore] = NULL;
						clear_bit(semaphore, ctx->imm_inbox_semaphore_bitmap);
					}
				}
				
				if(GET_POST_RECEIVE_DEPTH_FROM_POST_RECEIVE_ID(wc[i].wr_id)%(ctx->rx_depth/4) == ((ctx->rx_depth/4)-1))
				{
					connection_id = client_find_qp_id_by_qpnum(ctx, wc[i].qp->qp_num);	
					client_post_receives_message(ctx, connection_id, ctx->rx_depth/4);
					/*
					recv = (struct send_and_reply_format *)kmalloc(sizeof(struct send_and_reply_format), GFP_KERNEL); //kmem_cache_alloc(s_r_cache, GFP_KERNEL);
					recv->length = ctx->rx_depth/4;
					recv->src_id = connection_id;
					recv->type = MSG_DO_RC_POST_RECEIVE;

					spin_lock(&wq_lock);
					list_add_tail(&(recv->list), &request_list.list);
					spin_unlock(&wq_lock);
					*/
				}
			}
			else
			{	
				connection_id = client_find_qp_id_by_qpnum(ctx, wc[i].qp->qp_num);
				printk(KERN_ALERT "%s: connection %d Recv weird event as %d\n", __func__, connection_id, (int)wc[i].opcode);
			}

		}
		schedule();
	}
	return 0;
}

int client_poll_cq_pass(void *in)
{
	struct thread_pass_struct *input = (struct thread_pass_struct *)in;
	printk(KERN_CRIT "%s: target_cq %p\n", __func__, input->target_cq);
	client_poll_cq(input->ctx, input->target_cq);
	kfree(input);
	printk(KERN_CRIT "%s: kill ctx %p cq %p\n", __func__, (void *)input->ctx, (void *)input->target_cq);
	return 0;
}

void client_setup_ibapi_header(uint32_t src_id, uint64_t inbox_addr, uint64_t inbox_semaphore, uint32_t length, int priority, int type, struct ibapi_header *output_header)
{
	output_header->src_id = src_id;
	output_header->inbox_addr = inbox_addr;
	output_header->inbox_semaphore = inbox_semaphore;
	output_header->length = length;
	output_header->priority = priority;
	output_header->type = type;
}

int client_send_cq_poller(ppc *ctx)
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

int client_send_request(ppc *ctx, int connection_id, enum mode s_mode, struct client_ibv_mr *input_mr, void *addr, int size, int offset, int userspace_flag)
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
		tempaddr = client_ib_reg_mr_addr(ctx, addr, size);
		sge.addr = tempaddr;
	}
	sge.length = size;
	sge.lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	if(!ret)
	{
		client_internal_poll_sendcq(ctx->send_cq[connection_id], connection_id, &poll_status);
	}
	else
	{
		printk(KERN_INFO "%s: send fail %d\n", __func__, connection_id);
	}
	return 0;
}

inline int client_get_inbox_by_addr(ppc *ctx, void *addr)
{
	int tar;
	spin_lock(&ctx->imm_inbox_semaphore_lock);

	tar = find_first_zero_bit(ctx->imm_inbox_semaphore_bitmap, IMM_NUM_OF_SEMAPHORE);
	while(tar==IMM_NUM_OF_SEMAPHORE)
	{
		schedule();
		tar = find_first_zero_bit(ctx->imm_inbox_semaphore_bitmap, IMM_NUM_OF_SEMAPHORE);
	}
	set_bit(tar, ctx->imm_inbox_semaphore_bitmap);	

	spin_unlock(&ctx->imm_inbox_semaphore_lock);
	ctx->imm_inbox_semaphore[tar] = addr;

	return tar;
}

int client_send_reply_with_rdma_write_with_imm(ppc *ctx, int target_node, void *addr, int size, void *ret_addr, int max_ret_size, int userspace_flag)
{
	int tar_offset_start;
	int connection_id;
	int inbox_id;
	int imm_data;
	int wait_send_reply_id = SEND_REPLY_WAIT;
	int real_size = size + sizeof(struct imm_message_metadata);
	void *remote_addr;
	uint32_t remote_rkey;
	struct client_ibv_mr *remote_mr;
	struct imm_message_metadata output_header;
	unsigned long phys_addr;
	
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

	if(tar_offset_start==REG_DO_QUERY_FIRST)
	{
		printk(KERN_CRIT "%s: can't find node %d\n", __func__, target_node);
		return REG_DO_QUERY_FIRST;
	}
	
	remote_mr = &(ctx->remote_rdma_ring_mrs[target_node]);

retry_send_reply_with_imm_request:

	connection_id = client_get_connection_by_atomic_number(ctx, target_node, LOW_PRIORITY);
	inbox_id = client_get_inbox_by_addr(ctx, &wait_send_reply_id);
	
	imm_data = IMM_SEND_REPLY_SEND | tar_offset_start; 
	
	output_header.inbox_addr = client_ib_reg_mr_addr(ctx, ret_addr, max_ret_size);//This part need to be handled careful in the future
	output_header.inbox_rkey = ctx->proc->rkey;
	output_header.inbox_semaphore = inbox_id;
	output_header.source_node_id = ctx->node_id;
	output_header.size = size;
	remote_addr = remote_mr->addr;
	remote_rkey = remote_mr->rkey;
	//printk(KERN_CRIT "%s: send imm-%x addr-%x rkey-%x oaddr-%x orkey-%x\n", __func__, imm_data, remote_addr, remote_rkey, output_header.inbox_addr, output_header.inbox_rkey);

#ifdef SCHEDULE_MODEL
	ctx->imm_inbox_semaphore_task[inbox_id] = get_current();
	set_current_state(TASK_INTERRUPTIBLE);
#endif
	client_send_message_with_rdma_write_with_imm_request(ctx, connection_id, remote_rkey, 
			(uintptr_t)remote_addr, addr, size, tar_offset_start, imm_data, 
			FIT_SEND_MESSAGE_HEADER_AND_IMM, &output_header, FIT_KERNELSPACE_FLAG);

#ifdef SCHEDULE_MODEL
	schedule();
	set_current_state(TASK_RUNNING);
#endif

#ifdef CURELAX_MODEL
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
		goto retry_send_reply_with_imm_request;
	}

	return wait_send_reply_id;
}

int client_send_request_without_polling(ppc *ctx, int connection_id, enum mode s_mode, struct client_ibv_mr *input_mr, void *addr, int size, int offset, int wr_id)
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
	tempaddr = client_ib_reg_mr_addr(ctx, addr, size);
	sge.addr = tempaddr;
	sge.length = size;
	sge.lkey = ctx->proc->lkey;
	
	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	if(ret)
		printk("Error in [%s] ret:%d \n", __func__, ret);
	
	return 0;
}

int client_send_request_polling_only(ppc *ctx, int connection_id, int polling_num, struct ib_wc *wc)
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

void client_free_recv_buf(void *input_buf)
{
	kfree(input_buf);
	//kmem_cache_free(post_receive_cache, input_buf);
}

int client_send_test(ppc *ctx, int connection_id, int type, void *addr, int size, uint64_t inbox_addr, uint64_t inbox_semaphore, int priority)
{	
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge;
	int ret;
	int ne, i;
	struct ib_wc wc[2];
	struct ibapi_header output_header;
	void *output_header_addr;

	printk(KERN_CRIT "%s conn %d addr %p size %d sendcq %p\n", __func__, connection_id, addr, size, ctx->send_cq[connection_id]);
	spin_lock(&connection_lock[connection_id]);

	memset(&wr, 0, sizeof(wr));

	sge.addr = (uintptr_t)client_ib_reg_mr_addr(ctx, addr, size);
	sge.length = size;
	sge.lkey = ctx->proc->lkey;
	printk(KERN_CRIT "%s registered addr %lx lkey %d\n", sge.addr, sge.lkey);

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

int client_send_message_lego(ppc *ctx, int connection_id, int type, void *addr, int size, uint64_t inbox_addr, uint64_t inbox_semaphore, int priority)
{	
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge[1];
	int ret;
	int ne, i;
	struct ib_wc wc[2];
	struct ibapi_header output_header;
	void *output_header_addr;

	printk(KERN_CRIT "%s conn %d addr %p size %d sendcq %p\n", __func__, connection_id, addr, size, ctx->send_cq[connection_id]);
	spin_lock(&connection_lock[connection_id]);

	memset(&wr, 0, sizeof(wr));
	memset(sge, 0, sizeof(struct ib_sge)*2);

	wr.wr_id = type;
	wr.opcode = IB_WR_SEND;
	wr.sg_list = sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_SIGNALED;

	sge[0].addr = (uintptr_t)client_ib_reg_mr_addr(ctx, addr, size);
	sge[0].length = size;
	sge[0].lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	printk(KERN_CRIT "%s headeraddr %p %p bufaddr %p %p lkey %d\n",
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

int client_send_message_sge(ppc *ctx, int connection_id, int type, void *addr, int size, uint64_t inbox_addr, uint64_t inbox_semaphore, int priority)
{	
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge[1];
	int ret;
	int ne, i;
	struct ib_wc wc[2];
	struct ibapi_header output_header;
	void *output_header_addr;

	printk(KERN_CRIT "%s conn %d addr %p size %d sendcq %p\n", __func__, connection_id, addr, size, ctx->send_cq[connection_id]);
	spin_lock(&connection_lock[connection_id]);

	memset(&wr, 0, sizeof(wr));
	memset(sge, 0, sizeof(struct ib_sge)*2);

	wr.wr_id = type;
	wr.opcode = IB_WR_SEND;
	wr.sg_list = sge;
	wr.num_sge = 1;
	wr.send_flags = IB_SEND_SIGNALED;

/*
	client_setup_ibapi_header(ctx->node_id, inbox_addr, inbox_semaphore, size, priority, type, &output_header);
	output_header_addr = (void *)client_ib_reg_mr_addr(ctx, &output_header, sizeof(struct ibapi_header));
	sge[0].addr = (uintptr_t)output_header_addr;
	sge[0].length = sizeof(struct ibapi_header);
	sge[0].lkey = ctx->proc->lkey;
*/
	sge[0].addr = (uintptr_t)client_ib_reg_mr_addr(ctx, addr, size);
	sge[0].length = size;
	sge[0].lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	printk(KERN_CRIT "%s headeraddr %p %p bufaddr %p %p lkey %d\n",
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

int send_rdma_ring_mr_to_other_nodes(ppc *ctx)
{
	int i;
	int connection_id;
	char *msg;
	int ret;

	msg = kmalloc(sizeof(struct client_ibv_mr), GFP_KERNEL);
	for (i = 0; i < ctx->num_node; i++) {
		if (ctx->node_id == i)
			continue;
		memcpy(msg, &ctx->local_rdma_ring_mrs[i], sizeof(struct client_ibv_mr)); 
		connection_id = 0; // XXX NUM_PARALLEL_CONNECTION * i;
		printk(KERN_CRIT "%s send ringmr addr %p lkey %lx rkey %lx conn %d\n",
				__func__, ctx->local_rdma_ring_mrs[i].addr,
				ctx->local_rdma_ring_mrs[i].lkey, 
				ctx->local_rdma_ring_mrs[i].rkey, connection_id);
		//ret = client_send_test(ctx, connection_id, MSG_SEND_RDMA_RING_MR, msg, sizeof(struct client_ibv_mr), 0, 0, LOW_PRIORITY);
		ret = client_send_message_sge(ctx, connection_id, MSG_SEND_RDMA_RING_MR, msg, sizeof(struct client_ibv_mr), 0, 0, LOW_PRIORITY);
	}
	kfree(msg);

	return ret;
}

ppc *client_establish_conn(struct ib_device *ib_dev, int ib_port, int mynodeid)
{
	int     ret;
	int     i;
        int             temp_ctx_number;
	ppc *ctx;
        temp_ctx_number = atomic_inc_return(&Connected_FIT_Num);
	struct client_ibv_mr *ret_mr;
	//struct task_struct *thread;
	struct thread_pass_struct thread_pass_poll_cq;
	int num_connected_nodes = 0;
	num_recvd_rdma_ring_mrs = 0;

        if(temp_ctx_number>=MAX_FIT_NUM)
        {
                printk(KERN_CRIT "%s Error: already meet the upper bound of connected FIT %d\n", __func__, temp_ctx_number);
                atomic_dec(&Connected_FIT_Num);
                return 0;
        }
	
	printk(KERN_CRIT "Start establish connection node %d\n", mynodeid);
	init_global_lid_qpn();

	ctx = client_init_interface(ib_port, ib_dev);
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
	//Initialize waiting_queue/request list related items
	spin_lock_init(&wq_lock);
//	INIT_LIST_HEAD(&(request_list.list));

	//Initialize multicast spin_lock
	spin_lock_init(&multicast_lock);

	//Start handling completion cq
	thread_pass_poll_cq.ctx = ctx;
	thread_pass_poll_cq.target_cq = ctx->cq[0];
	//kernel_thread(client_poll_cq_pass, &thread_pass_poll_cq, 0);
	//wake_up_process(thread);
	
	printk(KERN_CRIT "%s created poll cq thread\n", __func__);

#if SEPARATE_SEND_POLL_THREAD
	thread = kthread_create((void *)client_send_cq_poller, ctx, "separate_poll_send");
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
	ctx->local_rdma_ring_mrs = (struct client_ibv_mr *)kmalloc(MAX_NODE * sizeof(struct client_ibv_mr), GFP_KERNEL);
	for(i=0; i<MAX_NODE; i++)
	{
		ctx->local_rdma_recv_rings[i] = client_alloc_memory_for_mr(IMM_PORT_CACHE_SIZE);
		ret_mr = client_ib_reg_mr(ctx, ctx->local_rdma_recv_rings[i], IMM_RING_SIZE,
				IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ);
		memcpy(&ctx->local_rdma_ring_mrs[i], ret_mr, sizeof(struct client_ibv_mr *));
	}
	/* array to store rdma ring mr for all remote nodes */
	ctx->remote_rdma_ring_mrs = (struct client_ibv_mr *)kmalloc(MAX_NODE * sizeof(struct client_ibv_mr), GFP_KERNEL);
	ctx->remote_rdma_ring_mrs_offset = (unsigned long *)kzalloc(MAX_NODE * sizeof(unsigned long), GFP_KERNEL);
	ctx->remote_imm_offset_lock = (spinlock_t *)kmalloc(MAX_NODE * sizeof(spinlock_t), GFP_KERNEL); 
	for(i=0; i<MAX_NODE; i++)
		spin_lock_init(&ctx->remote_imm_offset_lock[i]);

	printk(KERN_CRIT "%s allocated local rdma buffers, about to connect qps\n", __func__);
	ctx->node_id = mynodeid;
	for (i = 0; i < mynodeid; i++) {
		client_add_newnode(ctx, i);
		num_connected_nodes++;
	}

	//if (num_connected_nodes == mynodeid - 1) {
		for (i = mynodeid + 1; i < MAX_NODE; i++) {
			client_add_newnode(ctx, i);
			num_connected_nodes ++;
		}
	//}
	printk(KERN_CRIT "%s all connections completed\n", __func__);
	//schedule();

	if (ctx->node_id == 0)
		send_rdma_ring_mr_to_other_nodes(ctx);
	else
		client_poll_cq_pass(&thread_pass_poll_cq);
	printk(KERN_CRIT "%s sent rdma ring mrs\n", __func__);

	//schedule();

	while (num_recvd_rdma_ring_mrs < ctx->num_node - 1)
		//cpu_relax();
		schedule();

	printk(KERN_ALERT "%s: return before establish connection with NODE_ID: %d\n", __func__, ctx->node_id);

	return ctx;
}

int client_cleanup_module(void)
{
	printk(KERN_INFO "Ready to remove module\n");
	return 0;
}

int fit_internal_init(void)
{
        Connected_Ctx = (ppc **)kmalloc(sizeof(ppc*)*MAX_FIT_NUM, GFP_KERNEL);
        atomic_set(&Connected_FIT_Num, 0);
	printk(KERN_CRIT "insmod fit_internal module\n");
	return 0;
}

int fit_internal_cleanup(void)
{
	printk(KERN_CRIT "rmmod fit_internal module\n");
	return 0;
}
