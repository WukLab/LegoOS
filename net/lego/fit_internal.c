/*
 * Copyright (c) 2016-2020 Wuklab, Purdue University. All rights reserved.
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
#include <lego/kthread.h>
#include <lego/workqueue.h>
#include <lego/list.h>
#include <lego/string.h>
#include <lego/jiffies.h>
#include <lego/pci.h>
#include <lego/delay.h>
#include <lego/slab.h>
#include <lego/time.h>
#include <lego/timer.h>
#include <lego/kernel.h>
#include <lego/fit_ibapi.h>
#include <lego/comp_common.h>
#include <lego/profile.h>
#include <rdma/ib_verbs.h>

#include <processor/pcache.h>
#include <memory/thread_pool.h>

#include "fit_internal.h"

#ifdef CONFIG_FIT_DEBUG
#define fit_debug(fmt, ...) \
	pr_debug("%s():%d " fmt, __func__, __LINE__, __VA_ARGS__)
#else
static inline void fit_debug(const char *fmt, ...) { }
#endif

#define fit_err(fmt, ...)						\
	pr_debug("%s()-%d CPU%2d " fmt "\n",				\
		__func__, __LINE__, smp_processor_id(), __VA_ARGS__)

static int ib_port = 1;
enum ib_mtu mtu;
static int sl;
static int nr_joined_nodes = 0;

/*
 * This is used by FIT internal thread: wq_handler
 * This thread is a background thread that will send async messages
 * or other actions on behalf of caller. Requests are posted through
 * enqueue_wq(), and the worker thread uses dequeue_wq().
 */
static DEFINE_SPINLOCK(wq_lock);
static atomic_t nr_wq_jobs;
static struct send_and_reply_format request_list;

static inline void enqueue_wq(struct send_and_reply_format *new)
{
	spin_lock(&wq_lock);
	list_add_tail(&new->list, &(request_list.list));
	atomic_inc(&nr_wq_jobs);
	spin_unlock(&wq_lock);
}

static inline struct send_and_reply_format *dequeue_wq(void)
{
	struct send_and_reply_format *p;

	spin_lock(&wq_lock);
	p = list_first_entry(&(request_list.list),
			     struct send_and_reply_format, list);
	list_del(&p->list);
	atomic_dec(&nr_wq_jobs);
	spin_unlock(&wq_lock);

	return p;
}

/**
 * gets the page table entry for input address
 * @mm: memory struct
 * @addr: input address
 */
static __always_inline pte_t *fit_get_pte(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, addr);
	if (unlikely(pgd_none(*pgd)))
		return 0;

	pud = pud_offset(pgd, addr);
	if (unlikely(pud_none(*pud)))
		return 0;

	pmd = pmd_offset(pud, addr);
	if (unlikely(pmd_none(*pmd)))
		return 0;

	pte = pte_offset(pmd, addr);
	if (unlikely(pte_none(*pte)))
		return 0;

	return pte;
}

/*
 * Checking if user-level virtual mem address map to contiguous physical memory address
 */
__used static int fit_check_page_continuous(void *local_addr,
				     int size, unsigned long *answer)
{
	pte_t *pte;
	struct page *page;
	unsigned long ret_phys_addr;
	unsigned long test_phys_addr;
	void *test_addr;

	pte = fit_get_pte(current->mm, (unsigned long)local_addr);
	if(!pte)
		return 0;
	page = pte_page(*pte);
	ret_phys_addr = page_to_phys(page) + (((uintptr_t)local_addr) & FIT_LINUX_PAGE_OFFSET);

	test_addr = local_addr + size - 1;
	pte = fit_get_pte(current->mm, (unsigned long)test_addr);
	if(!pte)
		return 0;
	page = pte_page(*pte);
	test_phys_addr = page_to_phys(page) + (((uintptr_t)test_addr) & FIT_LINUX_PAGE_OFFSET);

	/* non-contiguous */
	if(test_phys_addr != ret_phys_addr + size - 1)
	{
		return 0;
	}
	*answer = ret_phys_addr;

	return 1;
}

static inline void *get_reply_ready_ptr(ppc *ctx, unsigned int index)
{
	void *ptr;
	unsigned long *bitmap = ctx->reply_ready_indicators_bitmap;

	if (unlikely(index >= IMM_NUM_OF_SEMAPHORE)) {
		fit_err("array_size: %d index: %d",
			IMM_NUM_OF_SEMAPHORE, index);
		BUG();
	}

	ptr = ctx->reply_ready_indicators[index];

	if (unlikely(!test_bit(index, bitmap))) {
		fit_err("index: %d ptr: %p", index, ptr);
		dump_stack();
		hlt();
	}

	if (unlikely(!virt_addr_valid((unsigned long)ptr))) {
		fit_err("index: %d ptr: %p", index, ptr);
		BUG();
	}
	return ptr;
}

static inline void free_reply_indicator(ppc *ctx, unsigned int idx)
{
	unsigned long *bitmap = ctx->reply_ready_indicators_bitmap;

	if (unlikely(idx >= IMM_NUM_OF_SEMAPHORE)) {
		fit_err("array_size: %d index: %d",
			IMM_NUM_OF_SEMAPHORE, idx);
		BUG();
	}

	spin_lock(&ctx->indicators_lock);
	if (likely(test_and_clear_bit(idx, bitmap)))
		ctx->reply_ready_indicators[idx] = NULL;
	else {
		fit_err("index: %d", idx);
		BUG();
	}
	spin_unlock(&ctx->indicators_lock);
}

/*
 * @addr: must be a valid kernel virtual address
 */
static inline unsigned int alloc_index_and_set_reply_indicator(ppc *ctx, void *addr)
{
	int idx;
	unsigned long *bitmap = ctx->reply_ready_indicators_bitmap;

retry:
	spin_lock(&ctx->indicators_lock);
	for_each_clear_bit(idx, bitmap, IMM_NUM_OF_SEMAPHORE) {
		set_bit(idx, bitmap);
		ctx->reply_ready_indicators[idx] = addr;
		spin_unlock(&ctx->indicators_lock);
		return idx;
	}
	spin_unlock(&ctx->indicators_lock);

	/*
	 * All full? Given the fact that we are using sync RPC,
	 * the maximum outstanding requests will equal to nr_cpus.
	 * Show correct warnings here.
	 */
	if (likely(IMM_NUM_OF_SEMAPHORE <= nr_cpus)) {
		WARN_ONCE(1, "Please set a larger IMM_NUM_OF_SEMAPHORE.");
		goto retry;
	}
	BUG();
}

#ifdef CONFIG_SOCKET_O_IB
int init_socket_over_ib(struct lego_context *ctx, int port, int rx_depth, int i)
{
	pr_info("%s mynodeid %d remote node %d\n", __func__, ctx->node_id, i);

	ctx->sock_send_cq[i] = ib_create_cq((struct ib_device *)ctx->context, NULL, NULL, NULL, rx_depth+1, 0);
	if (IS_ERR_OR_NULL(ctx->sock_send_cq[i])) {
		fit_err("Fail to create sock_send_cq[%d]. Error: %d",
			i, PTR_ERR_OR_ZERO(ctx->sock_send_cq[i]));
		return -EIO;
	}

	struct ib_qp_attr attr;
	struct ib_qp_init_attr init_attr = {
		.send_cq = ctx->sock_send_cq[i],
		.recv_cq = ctx->sock_recv_cq,
		.cap = {
			.max_send_wr = MAX_OUTSTANDING_SEND,
			.max_recv_wr = rx_depth,
			.max_send_sge = 16,
			.max_recv_sge = 16
		},
		.qp_type = IB_QPT_RC,
		.sq_sig_type = IB_SIGNAL_REQ_WR
	};

	ctx->sock_qp[i] = ib_create_qp(ctx->pd, &init_attr);
	if(IS_ERR_OR_NULL(ctx->sock_qp[i]))
	{
		printk(KERN_ALERT "Fail to create sock_qp. Error: %d\n",
			PTR_ERR_OR_ZERO(ctx->sock_qp[i]));
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
static int qpn_aligned = false;

static void align_first_qpn(struct ib_pd *pd, struct ib_qp_init_attr *init_attr)
{
	struct ib_qp *qp;
	int first = true;

	if (qpn_aligned)
		return;

next:
	qp = ib_create_qp(pd, init_attr);
	if (IS_ERR_OR_NULL(qp))
		panic("Fail to create QPs to align first QPN.");

	if (first) {
		pr_debug("To align first QPN, we skipped: #%d", qp->qp_num);
		first = false;
	}
		printk(KERN_CONT " #%d", qp->qp_num);

	if (qp->qp_num == (FIRST_QPN - 1)) {
		printk(KERN_CONT "\n");
		qpn_aligned = true;
		return;
	} else if (qp->qp_num > (FIRST_QPN - 1))
		panic("Initial alloc qpn: %d. align qpn: %d",
			qp->qp_num, FIRST_QPN);
	else
		goto next;
}

struct lego_context *fit_init_ctx(ppc *ctx, int size, int rx_depth, int port,
				  struct ib_device *ib_dev, int mynodeid)
{
	int i;
	int num_total_connections = MAX_CONNECTION;
	int rem_node_id;

	ctx->node_id = mynodeid;
	ctx->send_flags = IB_SEND_SIGNALED;
	ctx->rx_depth = rx_depth;
	ctx->num_connections = num_total_connections;
	ctx->num_node = MAX_NODE;
	ctx->num_parallel_connection = NUM_PARALLEL_CONNECTION;
	ctx->context = (struct ib_context *)ib_dev;
	ctx->channel = NULL;

	ctx->pd = ib_alloc_pd(ib_dev);
	if (IS_ERR_OR_NULL(ctx->pd)) {
		printk(KERN_ALERT "Fail to initialize pd / ctx->pd\n");
		return NULL;
	}

	ctx->proc = ib_get_dma_mr(ctx->pd, IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ);
	if (IS_ERR_OR_NULL(ctx->proc)) {
		pr_err("Fail to get dma mr\n");
		return NULL;
	}
	fit_debug("proc lkey %x rkey %x\n", ctx->proc->lkey, ctx->proc->rkey);

	ctx->send_state = kmalloc(num_total_connections * sizeof(enum s_state), GFP_KERNEL);
	ctx->recv_state = kmalloc(num_total_connections * sizeof(enum r_state), GFP_KERNEL);

	ctx->num_alive_connection = kmalloc(ctx->num_node*sizeof(atomic_t), GFP_KERNEL);
	atomic_set(&ctx->num_alive_nodes, 1);
	memset(ctx->num_alive_connection, 0, ctx->num_node*sizeof(atomic_t));
	for(i = 0; i < ctx->num_node; i++)
		atomic_set(&ctx->num_alive_connection[i], 0);

	ctx->send_cq_queued_sends = kmalloc(ctx->num_connections*sizeof(int), GFP_KERNEL);
	for(i = 0; i < ctx->num_connections; i++)
		ctx->send_cq_queued_sends[i] = 0;

	ctx->recv_num = kmalloc(ctx->num_connections*sizeof(int), GFP_KERNEL);
	memset(ctx->recv_num, 0, ctx->num_connections*sizeof(int));

	ctx->atomic_request_num = kmalloc(ctx->num_node*sizeof(atomic_t), GFP_KERNEL);
	memset(ctx->atomic_request_num, 0, ctx->num_node*sizeof(atomic_t));
	for(i=0;i<ctx->num_node;i++)
		atomic_set(&ctx->atomic_request_num[i], -1);

	atomic_set(&ctx->parallel_thread_num,0);
	atomic_set(&ctx->alive_connection, 0);
	atomic_set(&ctx->num_completed_threads, 0);

	ctx->atomic_buffer = kmalloc(num_total_connections * sizeof(struct atomic_struct *), GFP_KERNEL);
	ctx->atomic_buffer_total_length = kmalloc(num_total_connections * sizeof(int), GFP_KERNEL);
	for(i = 0; i < num_total_connections; i++)
		ctx->atomic_buffer_total_length[i]=0;

	ctx->atomic_buffer_cur_length = kmalloc(num_total_connections * sizeof(int), GFP_KERNEL);
	for(i = 0; i < num_total_connections; i++)
		ctx->atomic_buffer_cur_length[i]=-1;

	ctx->cq = kmalloc(NUM_POLLING_THREADS * sizeof(struct ib_cq *), GFP_KERNEL);
	if (!ctx->cq) {
		pr_err("OOM\n");
		return NULL;
	}

	for(i = 0; i < NUM_POLLING_THREADS; i++) {
		/*
		 * XXX
		 * why choose rx_depth*4+1 this maginc number? Reason???
		 */
		ctx->cq[i] = ib_create_cq((struct ib_device *)ctx->context, NULL, NULL, NULL,
					  rx_depth*4+1, 0);
		if (IS_ERR_OR_NULL(ctx->cq[i])) {
			fit_err("Fail to create recv_cq %d. Error: %d",
				i, PTR_ERR_OR_ZERO(ctx->cq[i]));
			return NULL;
		}
	}

	ctx->qp = kmalloc(num_total_connections * sizeof(struct ib_qp *), GFP_KERNEL);
	ctx->send_cq = kmalloc(num_total_connections * sizeof(struct ib_cq *), GFP_KERNEL);
	ctx->connection_count = kmalloc(num_total_connections * sizeof(atomic_t), GFP_KERNEL);
	for (i = 0; i < num_total_connections; i++)
		atomic_set(&ctx->connection_count[i], 0);

#ifdef CONFIG_SOCKET_O_IB
	ctx->sock_send_cq = (struct ib_cq **)kmalloc(MAX_NODE * sizeof(struct ib_cq *), GFP_KERNEL);
	ctx->sock_qp = (struct ib_qp **)kmalloc(MAX_NODE * sizeof(struct ib_qp *), GFP_KERNEL);
	ctx->sock_recv_cq = ib_create_cq((struct ib_device *)ctx->context, NULL, NULL, NULL, rx_depth+1, 0);
	BUG_ON(!ctx->sock_send_cq || !ctx->sock_recv_cq || !ctx->sock_qp);
#endif

	for (i = 0; i < num_total_connections; i++) {
		struct ib_qp_attr attr;

		memset(&attr, 0, sizeof(attr));

#ifdef CONFIG_SOCKET_O_IB
		rem_node_id = i/(NUM_PARALLEL_CONNECTION+1);
		fit_debug("sock enabled mynodeid %d i %d connecting node %d NUM_PARALLEL_CONNECTION %d \n",
				ctx->node_id, i, rem_node_id, NUM_PARALLEL_CONNECTION);
		if (rem_node_id == ctx->node_id)
			continue;
		/* last one for every remote node is a socket qp */
		if (i % (NUM_PARALLEL_CONNECTION+1) == NUM_PARALLEL_CONNECTION) {
			init_socket_over_ib(ctx, port, rx_depth, rem_node_id);
			continue;
		}
#else
		rem_node_id = i/NUM_PARALLEL_CONNECTION;
		fit_debug("mynodeid %d i %d connecting node %d\n", ctx->node_id, i, rem_node_id);
		if (rem_node_id == ctx->node_id)
			continue;
#endif
		ctx->send_state[i] = SS_INIT;
		ctx->recv_state[i] = RS_INIT;

		/*
		 * XXX
		 * why rx_depth+1 ???
		 */
		ctx->send_cq[i] = ib_create_cq((struct ib_device *)ctx->context, NULL, NULL, NULL,
						rx_depth+1, 0);
		if (IS_ERR_OR_NULL(ctx->send_cq[i])) {
			fit_err("Fail to create send_CQ-%d Error: %d\n",
				i, PTR_ERR_OR_ZERO(ctx->send_cq[i]));
			return NULL;
		}

		{
                struct ib_qp_init_attr init_attr = {
                        .send_cq = ctx->send_cq[i],
                        .recv_cq = ctx->cq[i % NUM_POLLING_THREADS],
                        .cap = {
                                .max_send_wr = MAX_OUTSTANDING_SEND,
                                .max_recv_wr = rx_depth,
                                .max_send_sge = 16,
                                .max_recv_sge = 16
                        },
                        .qp_type = IB_QPT_RC,
                        .sq_sig_type = IB_SIGNAL_REQ_WR
                };

		align_first_qpn(ctx->pd, &init_attr);

		ctx->qp[i] = ib_create_qp(ctx->pd, &init_attr);
		if (IS_ERR_OR_NULL(ctx->qp[i])) {
			fit_err("Fail to create qp[%d]. Error: %d",
				i, PTR_ERR_OR_ZERO(ctx->qp[i]));
			return NULL;
		}

		ib_query_qp(ctx->qp[i], &attr, IB_QP_CAP, &init_attr);
		if (init_attr.cap.max_inline_data >= size)
			ctx->send_flags |= IB_SEND_INLINE;

		}

		{
			struct ib_qp_attr attr1 = {
				.qp_state = IB_QPS_INIT,
				.pkey_index = 0,
				.port_num = port,
				.qp_access_flags = IB_ACCESS_REMOTE_WRITE|IB_ACCESS_REMOTE_READ|
						   IB_ACCESS_LOCAL_WRITE|IB_ACCESS_REMOTE_ATOMIC,
				.path_mtu = IB_MTU_2048,
				.retry_cnt = 7,
				.rnr_retry = 7
			};

			if (ib_modify_qp(ctx->qp[i], &attr1,
						IB_QP_STATE		|
						IB_QP_PKEY_INDEX	|
						IB_QP_PORT		|
						IB_QP_ACCESS_FLAGS)) {
				printk(KERN_ALERT "Fail to modify qp[%d]\n", i);
				ib_destroy_qp(ctx->qp[i]);
				return NULL;
			}
		}
	}

	/*
	 * Intentionlly set the 0 bitmap
	 */
	set_bit(0, ctx->reply_ready_indicators_bitmap);
	spin_lock_init(&ctx->indicators_lock);

	for (i=0;i<IMM_MAX_PORT;i++) {
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

	return ctx;
}

static inline uintptr_t
fit_ib_reg_mr_phys_addr(ppc *ctx, void *addr, size_t length)
{
	struct ib_device *ibd = (struct ib_device*)ctx->context;
	return (uintptr_t)phys_to_dma(ibd->dma_device, (phys_addr_t)addr);
}

static inline struct fit_ibv_mr *
fit_ib_reg_mr(ppc *ctx, void *addr, size_t length, enum ib_access_flags access)
{
	struct fit_ibv_mr *ret;
	struct ib_mr *proc;

	proc = ctx->proc;

	ret = (struct fit_ibv_mr *)kmalloc(sizeof(struct fit_ibv_mr), GFP_KERNEL);

#ifdef PHYSICAL_ALLOCATION
	ret->addr = (void *)fit_ib_reg_mr_phys_addr(ctx, (void *)virt_to_phys(addr), length);
#else
	ret->addr = (void *)ib_dma_map_single((struct ib_device *)ctx->context, addr, length, DMA_BIDIRECTIONAL);
#endif

	ret->length = length;
	ret->lkey = proc->lkey;
	ret->rkey = proc->rkey;
	ret->node_id = ctx->node_id;
	return ret;
}

static inline uintptr_t
fit_ib_reg_mr_addr_phys(ppc *ctx, void *addr, size_t length)
{
	return fit_ib_reg_mr_phys_addr(ctx, addr, length);
}

static inline uintptr_t
fit_ib_reg_mr_addr(ppc *ctx, void *addr, size_t length)
{
	return (uintptr_t)ib_dma_map_single((struct ib_device *)ctx->context,
					    addr, length, DMA_BIDIRECTIONAL);
}

DEFINE_PROFILE_POINT(fit_post_recv)

static int fit_post_receives_message(ppc *ctx, int connection_id, int depth)
{
	int i, ret;
	struct ib_recv_wr wr, *bad_wr = NULL;
	PROFILE_POINT_TIME(fit_post_recv)

	PROFILE_START(fit_post_recv);
	for (i = 0; i < depth; i++) {
		wr.wr_id = i + (connection_id << CONNECTION_ID_PUSH_BITS_BASED_ON_RECV_DEPTH);
		wr.next = NULL;
		wr.sg_list = NULL;
		wr.num_sge = 0;

		ret = ib_post_recv(ctx->qp[connection_id], &wr, &bad_wr);
		if (ret) {
			PROFILE_LEAVE(fit_post_recv);
			fit_err("Fail to post_recv conn_id: %d, i: %d, depth: %d",
				connection_id, i, depth);
			WARN_ON(1);
			return ret;
		}
	}
	PROFILE_LEAVE(fit_post_recv);
	return depth;
}

#ifdef CONFIG_SOCKET_O_IB
static int sock_post_receives_message(ppc *ctx, int connection_id, int depth)
{
	int i, ret;

	for(i=0;i<depth;i++)
	{
		struct ib_recv_wr wr, *bad_wr = NULL;
		wr.wr_id = i + (connection_id << CONNECTION_ID_PUSH_BITS_BASED_ON_RECV_DEPTH);
		wr.next = NULL;
		wr.sg_list = NULL;
		wr.num_sge = 0;
		ret = ib_post_recv(ctx->sock_qp[connection_id], &wr, &bad_wr);
		if (ret) {
			fit_err("Fail to post recv conn_id: %d", connection_id);
			WARN_ON(1);
			return ret;
		}
	}
	return depth;
}

int sock_post_receive_buffer(ppc *ctx, int connection_id, int depth)
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

static int fit_post_receives_message_with_buffer(ppc *ctx, int connection_id,
						 int depth)
{
	int i;
	char *buf, *header;
	uintptr_t header_addr;
	struct ibapi_post_receive_intermediate_struct *p_r_i_struct;
	uintptr_t addr;
	int size;
	int ret;

	fit_debug("conn %d post %d buffers\n", connection_id, depth);
#ifdef CONFIG_SOCKET_O_IB
	size = 2 * sizeof(struct fit_ibv_mr);
#else
	size = sizeof(struct fit_ibv_mr);
#endif
	for (i = 0; i < depth; i++) {
		struct ib_sge sge[2];
		struct ib_recv_wr wr, *bad_wr = NULL;

		buf = kmalloc(size, GFP_KERNEL);
		addr = fit_ib_reg_mr_addr(ctx, buf, size);

		header = kmalloc(sizeof(struct ibapi_header), GFP_KERNEL);
		header_addr = fit_ib_reg_mr_addr(ctx, header, sizeof(struct ibapi_header));

		p_r_i_struct = kmalloc(sizeof(struct ibapi_post_receive_intermediate_struct), GFP_KERNEL);
		p_r_i_struct->header = (uintptr_t)header_addr;
		p_r_i_struct->msg = (uintptr_t)addr;

		sge[0].addr = (uintptr_t)header_addr;
		sge[0].length = sizeof(struct ibapi_header);
		sge[0].lkey = ctx->proc->lkey;
		sge[1].addr = (uintptr_t)addr;
		sge[1].length = size;
		sge[1].lkey = ctx->proc->lkey;

		wr.wr_id = (uint64_t)p_r_i_struct;
		wr.next = NULL;
		wr.sg_list = sge;
		wr.num_sge = 2;
		ret = ib_post_recv(ctx->qp[connection_id], &wr, &bad_wr);
		if (ret) {
			printk(KERN_CRIT "ERROR: %s post recv error %d conn %d i %d\n",
				__func__, ret, connection_id, i);
			WARN_ON(1);
		}
		fit_debug("header %p header_addr %p buf %p addr %p lkey %d\n",
			header, header_addr, buf, addr, ctx->proc->lkey);
	}
	return depth;
}

#ifdef CONFIG_SOCKET_O_IB
int connect_sock_qp(ppc *ctx, int connection_id, int port, enum ib_mtu mtu, int sl, int destlid, int destqpn)
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

static int fit_connect_ctx(ppc *ctx, int connection_id, int port,
			   enum ib_mtu mtu, int sl, int destlid, int destqpn)
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

	fit_debug("connected conn %d destqpn %d\n", connection_id, destqpn);
	return 0;
}

static int get_global_qpn(int mynodeid, int remnodeid, int conn)
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
int sock_connect_nodes(ppc *ctx, int rem_node_id, int mynodeid)
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

static int fit_add_newnode(ppc *ctx, int rem_node_id, int mynodeid)
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
		fit_debug("cur connection %d mynode %d myqpn %d remnode %d remotelid %d remoteqpn %d\n",
			cur_connection, ctx->node_id, ctx->qp[cur_connection]->qp_num, rem_node_id, global_lid[rem_node_id], global_qpn);

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

/* XXX:should use radix or rb tree. */
static inline unsigned int fit_find_qp_id_by_qpnum(ppc *ctx, u32 qp_num)
{
        int i;

        for (i = 0; i < ctx->num_connections; i++) {
#ifdef CONFIG_SOCKET_O_IB
                if (i / (NUM_PARALLEL_CONNECTION + 1) == ctx->node_id)
                        continue;
                /* a socket qp */
                if (i % (NUM_PARALLEL_CONNECTION + 1) == NUM_PARALLEL_CONNECTION)
                        continue;
#else
		/* Skip myself */
                if (i / NUM_PARALLEL_CONNECTION == ctx->node_id)
                        continue;
#endif
                if (ctx->qp[i]->qp_num == qp_num)
                        return i;
        }
        return -1;
}

#ifdef CONFIG_SOCKET_O_IB
inline int fit_find_sock_qp_id_by_qpnum(ppc *ctx, uint32_t qp_num)
{
	int i;

	for(i = 0; i < MAX_NODE; i++)
	{
		/* does not support loop back currently */
		if (i == MY_NODE_ID)
			continue;
		if(ctx->sock_qp[i]->qp_num == qp_num)
			return i;
	}

	return -1;
}
#endif

/*
 * If we can not get the CQE within 20 seconds
 * There should be something wrong.
 */
#define FIT_POLL_CQ_TIMEOUT_NS	(20000000000L)

/*
 * HACK!!!
 *
 * This is a BLOCKING function call.
 * It will keep polling send_cq until we got the CQE for the just-sent-out WQE.
 * If you find dead loop here, ugh, I don't know what to do.
 *
 *
 * Return: -ETIMEDOUT if we fail to get the CQE in FIT_POLL_CQ_TIMEOUT_NS.
 */
static int fit_internal_poll_sendcq(ppc *ctx, struct ib_cq *tar_cq,
				    int connection_id, int *check, int if_poll_now)
{
#ifdef CONFIG_FIT_BATCH_POLL_SEND_CQ
	int ne, i;
	struct ib_wc wc[MAX_OUTSTANDING_SEND];
	unsigned long start_ns;

	/*
	 * use same send thread to poll send_cq
	 * but only poll once every MAX_OUTSTANDING_SEND/2 sends
	 */
	ctx->send_cq_queued_sends[connection_id]++;
	if (!if_poll_now &&
	    ctx->send_cq_queued_sends[connection_id] < MAX_OUTSTANDING_SEND/2)
		return 0;

	start_ns = sched_clock();
	do {
		if (if_poll_now)
			ne = ib_poll_cq(tar_cq, MAX_OUTSTANDING_SEND, wc);
		else
			ne = ib_poll_cq(tar_cq, MAX_OUTSTANDING_SEND/2, wc);

		if (ne < 0) {
			fit_err("Fail to poll send_cq. err=%d", ne);
			return ne;
		}

		if (unlikely(sched_clock() - start_ns > FIT_POLL_CQ_TIMEOUT_NS)) {
			pr_info_once("\n"
				"*****\n"
				"***** Fail to to get the CQE from send_cq (%p) after %ld seconds!\n"
				"***** CPU: %d connection_id: %d dest node: %d\n"
				"*****\n",
				tar_cq,
				FIT_POLL_CQ_TIMEOUT_NS/NSEC_PER_SEC,
				smp_processor_id(),
				connection_id, connection_id / NUM_PARALLEL_CONNECTION);
			WARN_ON_ONCE(1);
			return -ETIMEDOUT;
		}
	} while (ne < 1);

	for (i = 0; i < ne; i++) {
		if (wc[i].status != IB_WC_SUCCESS) {
			fit_err("wc.status: %s", ib_wc_status_msg(wc[i].status));
			return -EIO;
		}
	}
	ctx->send_cq_queued_sends[connection_id] -= ne;
	return 0;
#else

	/*
	 * This is the safest version.
	 * No batching, no any optimization.
	 */
	int ne, i;
	struct ib_wc wc[2];
	unsigned long start_ns;

	start_ns = sched_clock();
	do {
		ne = ib_poll_cq(tar_cq, 1, wc);
		if (unlikely(ne < 0)) {
			fit_err("Fail to poll send_cq. Err: %d", ne);
			return ne;
		}

		if (unlikely(sched_clock() - start_ns > FIT_POLL_CQ_TIMEOUT_NS)) {
			pr_info_once("\n"
				"*****\n"
				"***** Fail to to get the CQE from send_cq (%p) after %ld seconds!\n"
				"***** CPU: %d connection_id: %d dest node: %d\n"
				"*****\n",
				tar_cq,
				FIT_POLL_CQ_TIMEOUT_NS/NSEC_PER_SEC,
				smp_processor_id(),
				connection_id, connection_id / NUM_PARALLEL_CONNECTION);
			WARN_ON_ONCE(1);
			return -ETIMEDOUT;
		}
	} while (ne < 1);

	for (i = 0; i < ne; i++) {
		if (wc[i].status != IB_WC_SUCCESS) {
			fit_err("wc.status: %s", ib_wc_status_msg(wc[i].status));
			return -EIO;
		}
	}
	return 0;
#endif /* CONFIG_FIT_BATCH_POLL_SEND_CQ */
}

/*
 * This function is used a lot.
 * ibapi_send_reply uses this function to SEND msg to remote (then start polling).
 * and fit_ack_reply_callback() uses this function to REPLY.
 *
 * Basically, this will be used twice by one ibapi_send_reply().
 * Once at sender side, once at reply side.
 */
int fit_send_message_with_rdma_write_with_imm_request(ppc *ctx, int connection_id, uint32_t input_mr_rkey,
		uintptr_t input_mr_addr, void *addr, int size, int offset, uint32_t imm, enum mode s_mode,
		struct imm_message_metadata *header, int if_poll_now)
{
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge[2];
	uintptr_t temp_addr = 0;
	uintptr_t temp_header_addr = 0;
	int poll_status = SEND_REPLY_WAIT;
	int ret, poll_ret;

	/* XXX: not necessary. check and remove */
	memset(&wr, 0, sizeof(wr));
	memset(&sge, 0, sizeof(sge));

	wr.sg_list = sge;
	wr.wr.rdma.remote_addr = (uintptr_t)(input_mr_addr + offset);
	wr.wr.rdma.rkey = input_mr_rkey;

	fit_debug("wr: remotr_addr: %p, rkey: %#lx\n",
		wr.wr.rdma.remote_addr, wr.wr.rdma.rkey);

	if (s_mode == FIT_SEND_MESSAGE_HEADER_AND_IMM) {
		/*
		 * HACK!!!
		 *
		 * ibapi_send_reply() and ibapi_send() uses this mode to SEND.
		 * Check fit_send_reply_with_rdma_write_with_imm().
		 *
		 * If reply_indicator_index is -1, means this is ibapi_send()
		 */
		if (header->reply_indicator_index == -1)
			wr.wr_id = -1;
		else
			/* get the real local_reply_ready_checker address from inbox information */
			wr.wr_id = (u64)get_reply_ready_ptr(ctx, header->reply_indicator_index);

		wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;
		wr.ex.imm_data = imm;
		wr.send_flags = IB_SEND_SIGNALED;
		wr.num_sge = 2;

		/* Get the physical address of header */
		temp_header_addr = fit_ib_reg_mr_addr(ctx, header, sizeof(*header));
		sge[0].addr = temp_header_addr;
		sge[0].length = sizeof(struct imm_message_metadata);
		sge[0].lkey = ctx->proc->lkey;

		/* Get the physical address of user message */
		temp_addr = fit_ib_reg_mr_addr(ctx, addr, size);
		sge[1].addr = temp_addr;
		sge[1].length = size;
		sge[1].lkey = ctx->proc->lkey;

	} else if(s_mode == FIT_SEND_MESSAGE_IMM_ONLY) {
		/*
		 * HACK!!!
		 *
		 * fit_ack_reply_callback(), which is the REPLY part of
		 * ibapi_send_reply(), uses this mode to REPLY back!
		 *
		 * REPLY is the same as SEND, they are both RDMA_WRITE_IMM.
		 */
		wr.wr_id = (uint64_t)&poll_status;

		wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;
		wr.ex.imm_data = imm;
		wr.send_flags = IB_SEND_SIGNALED;
		wr.num_sge = 1;

		/* Get the physical address of user message */
		temp_addr = fit_ib_reg_mr_addr(ctx, addr, size);
		sge[0].addr = temp_addr;
		sge[0].length = size;
		sge[0].lkey = ctx->proc->lkey;

	} else if(s_mode == FIT_SEND_ACK_IMM_ONLY) {
		wr.wr_id = (uint64_t)&poll_status;
		wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;
		wr.ex.imm_data = imm;
		wr.send_flags = IB_SEND_SIGNALED;
		wr.num_sge = 0;
	} else {
		fit_err("wrong mode: %d", s_mode);
		BUG();
	}

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	if (unlikely(ret)) {
		pr_info_once("Fail to post send to con:%d ret:%d\n",
			connection_id, ret);
		WARN_ON_ONCE(1);
		return ret;
	}

	poll_ret = fit_internal_poll_sendcq(ctx, ctx->send_cq[connection_id],
				    connection_id, &poll_status, if_poll_now);
	if (unlikely(poll_ret == -ETIMEDOUT)) {
		pr_debug("mode: %d remote addr: %p, rkey: %#lx. "
			 "local addr: %p header: %p lkey: %#lx\n",
			s_mode, wr.wr.rdma.remote_addr, wr.wr.rdma.rkey,
			temp_addr, temp_header_addr, ctx->proc->lkey);
	}
	return 0;
}

inline int fit_get_connection_by_atomic_number(ppc *ctx, int target_node, int priority)
{
#ifdef CONFIG_SOCKET_O_IB
	return atomic_inc_return(&ctx->atomic_request_num[target_node]) % (atomic_read(&ctx->num_alive_connection[target_node]))
			+ (NUM_PARALLEL_CONNECTION +1) * target_node;
#else
	return atomic_inc_return(&ctx->atomic_request_num[target_node]) % (atomic_read(&ctx->num_alive_connection[target_node]))
			+ NUM_PARALLEL_CONNECTION * target_node;
#endif
}

int fit_receive_message_no_reply(ppc *ctx, unsigned int port, void *ret_addr, int receive_size, int userspace_flag)
{
	//This ret_addr is
	struct imm_message_metadata *tmp;
	int get_size;
	int offset;
	int node_id;
	struct imm_header_from_cq_to_port *new_request;
	int last_ack;
	int ack_flag=0;

	/*
	 * Busy polling incoming message
	 */
	while(1) {
		spin_lock(&ctx->imm_waitqueue_perport_lock[port]);
		if (likely(!list_empty(&(ctx->imm_waitqueue_perport[port].list)))) {
			new_request = list_entry(ctx->imm_waitqueue_perport[port].list.next,
						 struct imm_header_from_cq_to_port, list);
			list_del(&new_request->list);
			spin_unlock(&ctx->imm_waitqueue_perport_lock[port]);
			break;
		}
		spin_unlock(&ctx->imm_waitqueue_perport_lock[port]);
	}

	offset = new_request->offset;
	node_id = new_request->source_node_id;
	//printk(KERN_CRIT "%s got new req offset %d sourcenode %d\n", __func__, offset, node_id);
	//free list
	// XXX kmem_cache_free(imm_header_from_cq_to_port_cache, new_request);
	kfree(new_request);

	//get buffer from hash table based on node and port

	tmp = (struct imm_message_metadata *)(ctx->local_rdma_recv_rings[node_id] + offset);
	get_size = tmp->size;
	//Check size
	if(get_size > receive_size)
	{
		return SEND_REPLY_SIZE_TOO_BIG;
	}

	//do data memcpy
	memcpy(ret_addr, ((void *)tmp) + sizeof(struct imm_message_metadata), get_size);
	//printk(KERN_CRIT "%s: hash-%p offset-%x tmp-%p recv %s testport-%d testnodeid-%d\n", __func__, current_hash_ptr->addr, offset, tmp, ret_addr, tmp->designed_port, tmp->source_node_id);

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
		struct send_and_reply_format *pass;

		pass = kmalloc(sizeof(*pass), GFP_KERNEL);
		if (!pass)
			return -ENOMEM;

		pass->msg = (void *)(long)node_id;
		pass->length = offset;
		pass->type = MSG_DO_ACK_INTERNAL;

		enqueue_wq(pass);
	}

	return get_size;
}

#ifdef CONFIG_COMP_MEMORY
/*
 * Callback for thread pool
 */
void fit_ack_reply_callback(struct thpool_buffer *b)
{
	int last_ack, ack_flag = 0;
	int reply_size, node_id, offset;
	int reply_connection_id;
	void *reply_data;
	ppc *ctx;
	struct imm_message_metadata *request_metadata;

	ctx = b->fit_ctx;
	request_metadata = b->fit_imm;
	node_id = b->fit_node_id;
	offset = b->fit_offset;

	if (ThpoolBufferPrivateTX(b))
		reply_data = b->private_tx;
	else
		reply_data = b->tx;
	reply_size = b->tx_size;

	/*
	 * Step II
	 * FIT internal ACK
	 */
	spin_lock(&ctx->local_last_ack_index_lock[node_id]);
	last_ack = ctx->local_last_ack_index[node_id];
	if ((offset>= last_ack && offset - last_ack >= IMM_ACK_FREQ) ||
	    (offset< last_ack && offset + IMM_PORT_CACHE_SIZE - last_ack >= IMM_ACK_FREQ)) {
		ack_flag = 1;
		ctx->local_last_ack_index[node_id] = offset;
	}
	spin_unlock(&ctx->local_last_ack_index_lock[node_id]);

        if (ack_flag) {
                struct send_and_reply_format *pass;

                pass = kmalloc(sizeof(*pass), GFP_KERNEL);
                if (!pass) {
			WARN_ON_ONCE(1);
			return;
		}

                pass->msg = (void *)(long)node_id;
                pass->length = offset;
                pass->type = MSG_DO_ACK_INTERNAL;

		enqueue_wq(pass);
        }

	/* Comes from ibapi_send() */
	if (ThpoolBufferNoreply(b))
		return;

	/*
	 * Step III
	 * Reply message
	 */
        reply_connection_id = fit_get_connection_by_atomic_number(ctx, node_id, LOW_PRIORITY);

	/* Send it out. It is really a mess. */
	fit_send_message_with_rdma_write_with_imm_request(ctx, reply_connection_id,
			request_metadata->reply_rkey,
                        request_metadata->reply_addr,
			reply_data, reply_size, 0,
			request_metadata->reply_indicator_index | IMM_SEND_REPLY_RECV,
                        FIT_SEND_MESSAGE_IMM_ONLY, NULL, 1);
}
#endif

int fit_receive_message(ppc *ctx, unsigned int port, void *ret_addr, int receive_size, uintptr_t *reply_descriptor, int userspace_flag)
{
	//This ret_addr is
	struct imm_message_metadata *tmp;
	int get_size;
	int offset;
	int node_id;
	struct imm_message_metadata *descriptor;
	struct imm_header_from_cq_to_port *new_request;
	int last_ack;
	int ack_flag=0;

	/*
	 * Busy polling incoming message
	 */
	while(1) {
		spin_lock(&ctx->imm_waitqueue_perport_lock[port]);
		if (likely(!list_empty(&(ctx->imm_waitqueue_perport[port].list)))) {
			new_request = list_entry(ctx->imm_waitqueue_perport[port].list.next,
						 struct imm_header_from_cq_to_port, list);
			list_del(&new_request->list);
			spin_unlock(&ctx->imm_waitqueue_perport_lock[port]);
			break;
		}
		spin_unlock(&ctx->imm_waitqueue_perport_lock[port]);
	}

	offset = new_request->offset;
	node_id = new_request->source_node_id;
	//printk(KERN_CRIT "%s got new req offset %d sourcenode %d\n", __func__, offset, node_id);
	//free list
	// XXX kmem_cache_free(imm_header_from_cq_to_port_cache, new_request);
	kfree(new_request);

	//get buffer from hash table based on node and port

	tmp = (struct imm_message_metadata *)(ctx->local_rdma_recv_rings[node_id] + offset);
	get_size = tmp->size;
	//Check size
	if(get_size > receive_size)
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
	fit_debug("descriptor: %#lx, *reply_descriptor: %#lx\n", descriptor, *reply_descriptor);

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
		struct send_and_reply_format *pass;

		pass = kmalloc(sizeof(*pass), GFP_KERNEL);
		if (!pass)
			return -ENOMEM;

		pass->msg = (void *)(long)node_id;
		pass->length = offset;
		pass->type = MSG_DO_ACK_INTERNAL;
		enqueue_wq(pass);
	}

	return get_size;
}

int fit_reply_message(ppc *ctx, void *addr, int size, uintptr_t descriptor, int userspace_flag, int if_poll_now)
{
	struct imm_message_metadata *tmp = (struct imm_message_metadata *)descriptor;
	int re_connection_id = fit_get_connection_by_atomic_number(ctx, tmp->source_node_id, LOW_PRIORITY);

	fit_debug("re_connection_id: %d, tmp->source_node_id: %d\n",
		re_connection_id, tmp->source_node_id);

	/* Notice: if if_poll_now is 0, the message sent out here will not be polled and no guarantee of delivery */
	fit_send_message_with_rdma_write_with_imm_request(ctx, re_connection_id, tmp->reply_rkey,
			tmp->reply_addr, addr, size, 0, tmp->reply_indicator_index | IMM_SEND_REPLY_RECV,
			FIT_SEND_MESSAGE_IMM_ONLY, NULL, if_poll_now);
	// XXX kmem_cache_free(imm_message_metadata_cache, tmp);
	kfree(tmp);

	return 0;
}

int fit_reply_message_w_extra_bits(ppc *ctx, void *addr, int size, int private_bits, uintptr_t descriptor, int userspace_flag, int if_poll_now)
{
	int imm_data;
	struct imm_message_metadata *tmp = (struct imm_message_metadata *)descriptor;
	int re_connection_id = fit_get_connection_by_atomic_number(ctx, tmp->source_node_id, LOW_PRIORITY);

	fit_debug("re_connection_id: %d, tmp->source_node_id: %d\n",
		re_connection_id, tmp->source_node_id);

	imm_data = tmp->reply_indicator_index | IMM_SET_PRIVATE_BITS(private_bits) | IMM_REPLY_W_EXTRA_BITS;
	/* Notice: if if_poll_now is 0, the message sent out here will not be polled and no guarantee of delivery */
	fit_send_message_with_rdma_write_with_imm_request(ctx, re_connection_id, tmp->reply_rkey,
			tmp->reply_addr, addr, size, 0, imm_data,
			FIT_SEND_MESSAGE_IMM_ONLY, NULL, if_poll_now);
	// XXX kmem_cache_free(imm_message_metadata_cache, tmp);
	kfree(tmp);

	return 0;
}

#ifdef CONFIG_SOCKET_SYSCALL

int sock_receive_message(ppc *ctx, int *target_node, int port, void *ret_addr, int receive_size, int if_userspace, int sock_type)
{
	int get_size = 0;
	int offset;
	int node_id;
	struct sock_recved_msg_metadata *new_request = NULL, *temp_entry;
	int last_ack;
	int ack_flag=0;
	int total_received_size = 0;
	int already_copied_size = 0;

	fit_debug("port %d sock_type %x if_userspace %d\n", port, sock_type, if_userspace);

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
			fit_debug("got new req offset %d sourcenode %d size %d\n",
					offset, node_id, get_size);
			if (get_size > receive_size) {
				new_request->size -= receive_size;
				new_request->offset += receive_size;
				get_size = receive_size;
				sock_unset_read_ready(node_id, port, receive_size);
			} else {
				list_del(&new_request->list);
				sock_unset_read_ready(node_id, port, get_size);
			}

			break;
		}
		spin_unlock(&ctx->sock_imm_waitqueue_perport_lock[port]);

		if (get_size > 0)
			break;
		if ((sock_type & O_NONBLOCK) > 0) {
			fit_debug("nonblock break %d\n", total_received_size);
			return total_received_size;
		}
		schedule();
	}

	/*
	 * got all current requests
	 * return immediately for non-block socket
	 */
	if ((sock_type & O_NONBLOCK) > 0 && get_size == 0) {
		fit_debug("nonblock socket return when running out of received buffer %d\n", total_received_size);
		return total_received_size;
	}

	total_received_size += get_size;

	*target_node = node_id;
	fit_debug("adjusted new req offset %d sourcenode %d size %d\n",
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

		cp_ret = copy_to_user(ret_addr + already_copied_size, ctx->local_sock_rdma_recv_rings[node_id] + offset, get_size);
		WARN_ON(cp_ret);
	} else
		memcpy(ret_addr + already_copied_size, ctx->local_sock_rdma_recv_rings[node_id] + offset, get_size);
	already_copied_size += get_size;
	fit_debug("offset-%d recv %s srcnodeid-%d\n", offset, ret_addr, node_id);

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

		fit_debug("add ack req node %d offset %d\n", node_id, offset);
		enqueue_wq(pass);
	}

	if (total_received_size < receive_size) {
		fit_debug("go to next request received size %d total %d\n", total_received_size, receive_size);
		goto get_next_request;
	}

	return total_received_size;
}

int sock_send_message_with_rdma_imm(ppc *ctx, int target_node, uint32_t input_mr_rkey,
		uintptr_t input_mr_addr, void *addr, int size, int offset, uint32_t imm_data,
		void* header, int header_size, enum mode s_mode, int if_use_phys_addr_reg)
{
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge[2];
	int ret, i, ne;
	uintptr_t temp_addr, header_addr;
	int poll_status = SEND_REPLY_WAIT;
	struct ib_wc wc[1];

	fit_debug("%s target_node %d rkey %d mraddr %lx addr %p size %d offset %d imm-0x%x mode %d\n",
			__func__, target_node, input_mr_rkey, input_mr_addr, addr, size, offset, imm_data, s_mode);
	memset(&wr, 0, sizeof(struct ib_send_wr));
	memset(&sge, 0, sizeof(struct ib_sge));

	wr.sg_list = sge;
	wr.wr.rdma.remote_addr = (uintptr_t) (input_mr_addr+offset);
	wr.wr.rdma.rkey = input_mr_rkey;

	fit_debug("wr: remotr_addr: %p, rkey: %#lx header %p header size %d\n",
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

	ret = ib_post_send(ctx->sock_qp[target_node], &wr, &bad_wr);

	if(!ret)
	{
		do{
			ne = ib_poll_cq(ctx->sock_send_cq[target_node], 1, wc);
			if(ne < 0)
			{
				printk(KERN_ALERT "poll send_cq failed at send-qp\n");
				return 1;
			}
		}while(ne<1);
		for(i=0;i<ne;i++)
		{
			if(wc[i].status!=IB_WC_SUCCESS)
			{
				printk(KERN_ALERT "send failed at send-qp as %d\n", wc[i].status);
				return 2;
			}
		}
	}
	else
	{
		printk(KERN_INFO "%s: send fail %d ret %d\n", __func__, target_node, ret);
	}

	return 0;
}

/*
 * Return:
 * Negative values on failues
 * Positive values indicate the reply message length
 */
int sock_send_message(ppc *ctx, int target_node, int dest_port, int if_internal_port,
				void *addr, int size, unsigned long timeout_sec, int if_userspace)
{
	int tar_offset_start;
	int imm_data;
	int real_size = size + sizeof(int);
	void *remote_addr;
	uint32_t remote_rkey;
	struct fit_ibv_mr *remote_mr;
	int last_ack;
	int ret;
	int dest_port_data;
	unsigned long phys_addr;
	void *kbuf;

	if(size + sizeof(int) > IMM_MAX_SIZE)
	{
		printk(KERN_CRIT "%s: message size %d + header is larger than max size %d\n",
				__func__, size, IMM_MAX_SIZE);
		return -1;
	}
	if(!addr)
	{
		printk(KERN_CRIT "%s: null input addr\n", __func__);
		return -2;
	}

	spin_lock(&ctx->remote_sock_imm_offset_lock[target_node]);
	if(ctx->remote_sock_rdma_ring_mrs_offset[target_node] + real_size >= RDMA_RING_SIZE)//If hits the end of ring, write start from 0 directly
		ctx->remote_sock_rdma_ring_mrs_offset[target_node] = real_size;//Record the last point
	else
		ctx->remote_sock_rdma_ring_mrs_offset[target_node] += real_size;
	tar_offset_start = ctx->remote_sock_rdma_ring_mrs_offset[target_node] - real_size;//Trace back to the real starting point
	spin_unlock(&ctx->remote_sock_imm_offset_lock[target_node]);

	//printk(KERN_CRIT "%s tar_offset_start %d real_size %d last_ack_index %d\n",
	//		__func__, tar_offset_start, real_size, ctx->remote_last_ack_index[target_node]);
	//make sure does not over write than lastack
	while(1)
	{
		last_ack = ctx->remote_sock_last_ack_index[target_node];
		if(tar_offset_start < last_ack && tar_offset_start + real_size > last_ack)
			schedule();
		else
			break;
	}

	remote_mr = &(ctx->remote_sock_rdma_ring_mrs[target_node]);

	imm_data = SOCK_IMM_SEND | tar_offset_start;

	remote_addr = remote_mr->addr;
	remote_rkey = remote_mr->rkey;

	dest_port_data = dest_port | (if_internal_port << SOCK_IF_PORT_INTERNAL_BITS);
	fit_debug("send imm-0x%x addr-0x%x rkey-%x, tar offset %d dest port %d 0x%x\n",
		imm_data, remote_addr, remote_rkey, tar_offset_start, dest_port, dest_port_data);

	if (if_userspace) {
		ret = fit_check_page_continuous(addr, size, &phys_addr);
		if (ret == 1) {
			ret = sock_send_message_with_rdma_imm(ctx, target_node, remote_rkey,
					(uintptr_t)remote_addr, (void *)phys_addr, size, tar_offset_start, imm_data,
					&dest_port_data, sizeof(int),
					FIT_SEND_MESSAGE_HEADER_AND_IMM, 1);
		}
		else {
			kbuf = kmalloc(size, GFP_KERNEL);

			ret = copy_from_user(kbuf, addr, size);
			WARN_ON(ret);

			ret = sock_send_message_with_rdma_imm(ctx, target_node, remote_rkey,
					(uintptr_t)remote_addr, kbuf, size, tar_offset_start, imm_data,
					&dest_port_data, sizeof(int),
					FIT_SEND_MESSAGE_HEADER_AND_IMM, 0);
		}
	}
	else {
		ret = sock_send_message_with_rdma_imm(ctx, target_node, remote_rkey,
				(uintptr_t)remote_addr, addr, size, tar_offset_start, imm_data,
				&dest_port_data, sizeof(int),
				FIT_SEND_MESSAGE_HEADER_AND_IMM, 0);
	}

	return ret;
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

extern unsigned long	nr_recvcq_cqes[NUM_POLLING_THREADS];

/*
 * HACK!!!
 *
 * This function or thread, will poll the only recv_cq Lego has.
 * This recv_cq includes all incoming messages.
 * This thread is pinned to a cpu core and keep running.
 */
static int fit_poll_recv_cq(void *_info)
{
	ppc *ctx;
	char *addr;
	int recvcq_id;
	int ne, i, connection_id;
	int node_id, port, offset;
	int reply_indicator_index, length;
	struct ib_wc *wc;
	struct ib_cq *target_cq;
	struct thread_pass_struct *info = _info;

	/* Info passedd down by creater */
	ctx = info->ctx;
	target_cq = info->target_cq;
	recvcq_id = info->recvcq_id;

	wc = kmalloc(sizeof(*wc) * NUM_PARALLEL_CONNECTION, GFP_KERNEL);
	BUG_ON(!wc);

	if (pin_current_thread())
		panic("Fail to pin poll_cq");

	while(1) {
		/* We keep polling this CQ */
		do {
			ne = ib_poll_cq(target_cq, NUM_PARALLEL_CONNECTION, wc);
			if (unlikely(ne < 0)) {
				fit_err("poll_cq error: %d", ne);
				return ne;
			}
		} while (ne < 1);

		/* Update stats */
		nr_recvcq_cqes[recvcq_id] += ne;

		for (i = 0; i < ne; i++) {
			if (unlikely(wc[i].status != IB_WC_SUCCESS)) {
				fit_err("wc.status: %s, wr_id %d",
					ib_wc_status_msg(wc[i].status), wc[i].wr_id);
				continue;
			}

			/* IB_WC_RECV is only used at connection time */
			if (wc[i].opcode == IB_WC_RECV) {
				struct ibapi_post_receive_intermediate_struct *p_r_i_struct = (void *)wc[i].wr_id;
				struct ibapi_header temp_header;
				int type;

				fit_debug("received wr_id %lx type %d header %p",
					wc[i].wr_id, type, (void *)p_r_i_struct->header);

				memcpy(&temp_header, phys_to_virt(p_r_i_struct->header), sizeof(struct ibapi_header));
				addr = phys_to_virt(p_r_i_struct->msg);
				type = temp_header.type;

				if (type == MSG_SEND_RDMA_RING_MR) {
					memcpy(&ctx->remote_rdma_ring_mrs[temp_header.src_id],
					       addr, sizeof(struct fit_ibv_mr));
#ifdef CONFIG_SOCKET_O_IB
					memcpy(&ctx->remote_sock_rdma_ring_mrs[temp_header.src_id],
					       addr + sizeof(struct fit_ibv_mr), sizeof(struct fit_ibv_mr));
#endif

					nr_joined_nodes++;
					pr_debug(" ... Node [%2d] Joined. addr %p rkey %d nr_joined_nodes %d\n",
						temp_header.src_id, ctx->remote_rdma_ring_mrs[temp_header.src_id].addr,
						ctx->remote_rdma_ring_mrs[temp_header.src_id].rkey, nr_joined_nodes);
				}
			} else if (wc[i].opcode == IB_WC_RECV_RDMA_WITH_IMM) {
				/* IB_WC_WITH_IMM is the ONLY valid flag */
				if (wc[i].wc_flags != IB_WC_WITH_IMM) {
					fit_err("Unknown wc.wc_flags: %#lx", wc[i].wc_flags);
					WARN_ON_ONCE(1);
					return -EINVAL;
				}

				/* Following code assume wc_flags = IB_WC_WITH_IMM */
				node_id = GET_NODE_ID_FROM_POST_RECEIVE_ID(wc[i].wr_id);
				if (wc[i].ex.imm_data & IMM_SEND_REPLY_SEND) {
					/*
					 * This means there is an incoming request:
					 * the send part of ibapi_send_reply() from remote.
					 */
					offset = wc[i].ex.imm_data & IMM_GET_OFFSET;
					port = IMM_GET_PORT_NUMBER(wc[i].ex.imm_data);

#ifdef CONFIG_COMP_MEMORY
					{
					struct imm_message_metadata *tmp1;
                                        tmp1 = (struct imm_message_metadata *)(ctx->local_rdma_recv_rings[node_id] + offset);

					/* Enqueue this request to thpool */
                                        thpool_callback(ctx, tmp1,
							(void *)tmp1 + sizeof(struct imm_message_metadata),
                                                        tmp1->size, node_id, offset);
					}
#else
					{
					struct imm_header_from_cq_to_port *tmp;
					tmp = kmalloc(sizeof(*tmp), GFP_KERNEL);
					tmp->source_node_id = node_id;
					tmp->offset = offset;
					spin_lock(&ctx->imm_waitqueue_perport_lock[port]);
					list_add_tail(&(tmp->list), &ctx->imm_waitqueue_perport[port].list);
					spin_unlock(&ctx->imm_waitqueue_perport_lock[port]);
					}
#endif
				} else if (wc[i].ex.imm_data & IMM_SEND_REPLY_RECV) {
					/*
					 * This is the sender's handling reply part.
					 * The incoming message is the reply sent by remote.
					 */
					void *dst_ptr;

					length = wc[i].byte_len;
					reply_indicator_index = wc[i].ex.imm_data & IMM_GET_REPLY_INDICATOR_INDEX;
					if (unlikely(reply_indicator_index <= 0 ||
						     reply_indicator_index >= IMM_NUM_OF_SEMAPHORE)) {
						fit_err("Wrong index: %d", reply_indicator_index);
						WARN_ON_ONCE(1);
						continue;
					}

					/*
					 * The thread who did ibapi_send_reply() is busy polling
					 * this shared memory. This memcpy will release it.
					 */
					dst_ptr = get_reply_ready_ptr(ctx, reply_indicator_index);
					memcpy(dst_ptr, &length, sizeof(int));
				} else if (wc[i].ex.imm_data & IMM_ACK || wc[i].byte_len == 0) {
					struct send_and_reply_format *recv;

					/* Handle internal acknoledgement of new MR offset */
					offset = wc[i].ex.imm_data & IMM_GET_OFFSET;

					recv = kmalloc(sizeof(*recv), GFP_KERNEL);
					if (!recv) {
						WARN_ON_ONCE(1);
						return -ENOMEM;
					}
					recv->src_id = node_id;
					recv->msg = (char *)(long)offset;
					recv->type = MSG_DO_ACK_REMOTE;

					enqueue_wq(recv);
				} else if (wc[i].ex.imm_data & IMM_REPLY_W_EXTRA_BITS) {
					/* Handle reply with extra bits */
					int reply_data, private_bits;
					void *dst_ptr;

					length = wc[i].byte_len;
					reply_indicator_index = wc[i].ex.imm_data & IMM_GET_REPLY_INDICATOR_INDEX;
					private_bits = IMM_GET_PRIVATE_BITS(wc[i].ex.imm_data);
					reply_data = length << REPLY_PRIVATE_BITS_CNT | private_bits;

					fit_debug("extra bits index-%d len-%d bits-%x reply_indicator_addr %lx\n",
						reply_indicator_index, wc[i].byte_len, private_bits,
						ctx->reply_ready_indicators[reply_indicator_index]);

					dst_ptr = get_reply_ready_ptr(ctx, reply_indicator_index);
					memcpy(dst_ptr, &reply_data, sizeof(int));
				} else {
					fit_err("Unknown wc.ex.imm_data: %#lx", wc[i].ex.imm_data);
					WARN_ON_ONCE(1);
				}

				/*
				 * Post more recv_wr if needed.
				 */
				if ((GET_POST_RECEIVE_DEPTH_FROM_POST_RECEIVE_ID(wc[i].wr_id) % (ctx->rx_depth/4)) == ((ctx->rx_depth/4)-1)) {
					connection_id = fit_find_qp_id_by_qpnum(ctx, wc[i].qp->qp_num);
					if (connection_id == -1) {
						pr_crit("Error: cannot find qp number %d\n", wc[i].qp->qp_num);
						continue;
					}
					fit_post_receives_message(ctx, connection_id, ctx->rx_depth/4);
				}
			} else {
				/* Then it is unknown opcode */
				connection_id = fit_find_qp_id_by_qpnum(ctx, wc[i].qp->qp_num);
				fit_err("conn_id: %d Unknown wc.opcode: %d", connection_id, wc[i].opcode);
				WARN_ON_ONCE(1);
			}
		} /* end the loop for wc */
	}
	return 0;
}

#ifdef CONFIG_SOCKET_SYSCALL
/*
 * main polling function for all non-socket requests
 */
int sock_poll_cq(void *in)
{
	ppc *ctx;
	struct ib_cq *target_cq;
	int ne;
	struct ib_wc wc[NUM_PARALLEL_CONNECTION];
	int i, connection_id;
	int node_id, port, offset;
	int reply_indicator_index, length, opcode;
	char *addr;
	int type;
	struct send_and_reply_format *recv;
	int if_internal_port;
#ifdef NOTIFY_MODEL
	int test_result=0;
#endif
	struct imm_header_from_cq_to_port *tmp;
	struct sock_recved_msg_metadata *tmp_sock;
	//set_current_state(TASK_INTERRUPTIBLE);
	struct thread_pass_struct *input = (struct thread_pass_struct *)in;

	ctx = input->ctx;
	target_cq = input->target_cq;
	pr_info("***  recvpollcq runs on CPU%d\n", smp_processor_id());

	set_cpu_active(smp_processor_id(), false);

	while(1) {
		do {
			//set_current_state(TASK_RUNNING);
			ne = ib_poll_cq(target_cq, 1, wc);
			if (unlikely(ne < 0)) {
				printk(KERN_ALERT "poll CQ failed %d\n", ne);
				return 1;
			}
			if (ne == 0) {
				schedule();
			}
			//msleep(1);
		} while(ne < 1);

		for (i = 0; i < ne; i++) {
			connection_id = fit_find_sock_qp_id_by_qpnum(ctx, wc[i].qp->qp_num);
			if (connection_id == -1) {
				pr_crit("Error: cannot find qp number %d\n", wc[i].qp->qp_num);
				continue;
			}
			fit_debug("socket conn %d got one recv cq status %d opcode %d wr_id %d\n",
					connection_id, wc[i].status, wc[i].opcode, wc[i].wr_id);

			if (wc[i].status != IB_WC_SUCCESS)
				printk(KERN_ALERT "%s: failed status (%d) for wr_id %d\n", __func__, wc[i].status, (int) wc[i].wr_id);

			if ((int) wc[i].opcode == IB_WC_RECV) {
				fit_debug("Error: socket qp received normal send wr_id %lx\n", wc[i].wr_id);
			} else if ((int) wc[i].opcode == IB_WC_RECV_RDMA_WITH_IMM) {
				node_id = connection_id;
				fit_debug("got imm from node %d imm-0x%x\n", node_id, wc[i].ex.imm_data);
				if(wc[i].wc_flags&&IB_WC_WITH_IMM)
				{
					fit_debug("wc[i].ex.imm_data: %#lx wc[i].byte_len: %#lx\n", wc[i].ex.imm_data, wc[i].byte_len);
					if((wc[i].ex.imm_data & 0xF0000000) == SOCK_IMM_SEND) // only send
					{
						offset = wc[i].ex.imm_data & SOCK_IMM_GET_OFFSET;
						port = *((int*)(ctx->local_sock_rdma_recv_rings[node_id] + offset));
						fit_debug("got offset %d port %d %x %x\n", offset, port, port, port & SOCK_GET_IF_PORT_INTERNAL_BIT);
						if_internal_port = (port & SOCK_GET_IF_PORT_INTERNAL_BIT) >> SOCK_IF_PORT_INTERNAL_BITS;
						port = port & SOCK_GET_PORT;

						tmp_sock = (struct sock_recved_msg_metadata *)kmalloc(sizeof(struct sock_recved_msg_metadata), GFP_KERNEL); //kmem_cache_alloc(imm_header_from_cq_to_port_cache, GFP_KERNEL);
						tmp_sock->source_node_id = node_id;
						tmp_sock->offset = offset + sizeof(int);
						tmp_sock->size = wc[i].byte_len - sizeof(int);
						if (if_internal_port)
							tmp_sock->port = port;
						else
							tmp_sock->port = get_internal_port(MY_NODE_ID, port);
						fit_debug("received from node %d access to imm-0x%x offset %d port %d internal port %d mynode %d if-internal %d size %d\n",
								node_id, wc[i].ex.imm_data, offset, port, tmp_sock->port, MY_NODE_ID, if_internal_port, tmp_sock->size);
						spin_lock(&ctx->sock_imm_waitqueue_perport_lock[tmp_sock->port]);
						list_add_tail(&(tmp_sock->list), &ctx->sock_imm_waitqueue_perport[tmp_sock->port].list);
						spin_unlock(&ctx->sock_imm_waitqueue_perport_lock[tmp_sock->port]);
#if (CONFIG_EPOLL || CONFIG_POLL)
						sock_set_read_ready(node_id, tmp_sock->port, tmp_sock->size);
#endif
#ifdef CONFIG_EPOLL
						sock_epoll_callback(node_id, tmp_sock->port);
#endif
#ifdef CONFIG_POLL
						sock_poll_callback(node_id, tmp_sock->port);
#endif
					}
					else if(wc[i].ex.imm_data & SOCK_IMM_ACK || wc[i].byte_len == 0) // ack socket metadata
					{
						offset = wc[i].ex.imm_data & SOCK_IMM_GET_ACK_OFFSET;
						fit_debug("%s: get ack from node %d offset %d\n", __func__, node_id, offset);

						recv = (struct send_and_reply_format *)kmalloc(sizeof(struct send_and_reply_format), GFP_KERNEL); //kmem_cache_alloc(s_r_cache, GFP_KERNEL);
						recv->src_id = node_id;
						recv->msg = (char *)(long)offset;

						enqueue_wq(recv);
					}
					else //handle reply
					{
						void *dst_ptr;

						length = wc[i].byte_len;
						reply_indicator_index = wc[i].ex.imm_data & IMM_GET_REPLY_INDICATOR_INDEX;
						//printk(KERN_CRIT "%s: case 2 reply_indicator_index-%d len-%d\n", __func__, reply_indicator_index, wc[i].byte_len);

						fit_debug("case 2 reply_indicator_index-%d len-%d inboxaddr %lx\n",
							reply_indicator_index, wc[i].byte_len, ctx->reply_ready_indicators[reply_indicator_index]);

						dst_ptr = get_reply_ready_ptr(ctx, reply_indicator_index);
						memcpy(dst_ptr, &length, sizeof(int));
					}
				}

				if(GET_POST_RECEIVE_DEPTH_FROM_POST_RECEIVE_ID(wc[i].wr_id)%(ctx->rx_depth/4) == ((ctx->rx_depth/4)-1))
				{
					connection_id = fit_find_sock_qp_id_by_qpnum(ctx, wc[i].qp->qp_num);
					if (connection_id == -1) {
						pr_crit("Error: cannot find qp number %d\n", wc[i].qp->qp_num);
						continue;
					}
					sock_post_receives_message(ctx, connection_id, ctx->rx_depth/4);

#if 0
					recv = (struct send_and_reply_format *)kmalloc(sizeof(struct send_and_reply_format), GFP_KERNEL); //kmem_cache_alloc(s_r_cache, GFP_KERNEL);
					recv->length = ctx->rx_depth/4;
					recv->src_id = connection_id;
					recv->type = MSG_DO_RC_POST_RECEIVE;

					enqueue_wq(wq);
#endif
				}
			}
			else
			{
				connection_id = fit_find_sock_qp_id_by_qpnum(ctx, wc[i].qp->qp_num);
				printk(KERN_ALERT "%s: connection %d Recv weird event as %d\n", __func__, connection_id, (int)wc[i].opcode);
			}

		}
	}
	return 0;
}
#endif

static int waiting_queue_handler(void *_ctx)
{
	struct send_and_reply_format *new_request;
	int local_flag, last_ack, imm_data;
	ppc *ctx = _ctx;

	pin_current_thread();
	while (1) {
		while (!atomic_read(&nr_wq_jobs))
			cpu_relax();

		new_request = dequeue_wq();

		if (new_request->src_id == ctx->node_id)
			local_flag = 1;
		else
			local_flag = 0;

		switch (new_request->type) {
		case MSG_DO_RC_POST_RECEIVE:
			fit_post_receives_message(ctx, new_request->src_id, new_request->length);
			break;
		case MSG_DO_ACK_INTERNAL:
		{
			int offset = new_request->length;
			int target_node = (int)(long)new_request->msg;
			imm_data = IMM_ACK | offset;
#ifdef CONFIG_SOCKET_O_IB
			fit_send_message_with_rdma_write_with_imm_request(ctx, target_node * (NUM_PARALLEL_CONNECTION + 1),
					0, 0, 0, 0, 0, offset, FIT_SEND_ACK_IMM_ONLY, NULL, 0);
#else
			fit_send_message_with_rdma_write_with_imm_request(ctx, target_node * NUM_PARALLEL_CONNECTION,
					0, 0, 0, 0, 0, offset, FIT_SEND_ACK_IMM_ONLY, NULL, 0);
#endif
			break;
		}
		case MSG_DO_ACK_REMOTE:
			last_ack = (int)(long)new_request->msg;
			ctx->remote_last_ack_index[new_request->src_id] = last_ack;
			break;
#ifdef CONFIG_SOCKET_SYSCALL
		case MSG_SOCK_DO_ACK_INTERNAL:
		{
			int offset = new_request->length;
			int target_node = (int)(long)new_request->msg; //ptr->node;
			imm_data = SOCK_IMM_ACK | offset;
			sock_send_message_with_rdma_imm(ctx, target_node, 0, 0, 0, 0, 0,
							offset, NULL, 0,
							FIT_SEND_ACK_IMM_ONLY, FIT_KERNELSPACE_FLAG);
			break;
		}
		case MSG_SOCK_DO_ACK_REMOTE:
			last_ack = (int)(long)new_request->msg;
			ctx->remote_sock_last_ack_index[new_request->src_id] = last_ack;
			break;
#endif
		default:
			WARN_ON_ONCE(1);
			pr_info("%s: receive weird event %d\n", __func__, new_request->type);
		}

		/* It is our responsilibity to free the request */
		kfree(new_request);
	}
	BUG();
	return 0;
}

static void fit_setup_ibapi_header(uint32_t src_id, uint64_t reply_addr,
				   uint64_t reply_indicator_index,
				   uint32_t length, int priority, int type,
				   struct ibapi_header *msg_header)
{
	msg_header->src_id = src_id;
	msg_header->reply_addr = reply_addr;
	msg_header->reply_indicator_index = reply_indicator_index;
	msg_header->length = length;
	msg_header->priority = priority;
	msg_header->type = type;
}

int fit_send_request(ppc *ctx, int connection_id, enum mode s_mode,
			struct fit_ibv_mr *input_mr, void *addr,
			int size, int offset, int userspace_flag, int if_poll_now)
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
		fit_internal_poll_sendcq(ctx, ctx->send_cq[connection_id], connection_id, &poll_status, if_poll_now);
	}
	else
	{
		printk(KERN_INFO "%s: send fail %d\n", __func__, connection_id);
	}
	return 0;
}

/*
 * Return:
 * Negative values on failues
 * zero for succeed
 */
int fit_send_with_rdma_write_with_imm(ppc *ctx, int target_node, void *addr,
				      int size, int userspace_flag)
{
	int tar_offset_start;
	int connection_id;
	int imm_data;
	int real_size;
	void *remote_addr;
	uint32_t remote_rkey;
	struct fit_ibv_mr *remote_mr;
	struct imm_message_metadata msg_header;
	int last_ack;
	int ret;

	BUG_ON(!addr);

	real_size = size + sizeof(struct imm_message_metadata);
	if (unlikely(real_size > IMM_MAX_SIZE)) {
		fit_err("Size %d + header > %d", size, IMM_MAX_SIZE);
		return -EINVAL;
	}

	spin_lock(&ctx->remote_imm_offset_lock[target_node]);
	/* If hits the end of ring, write start from 0 directly */
	if (ctx->remote_rdma_ring_mrs_offset[target_node] + real_size >= RDMA_RING_SIZE)
		/* Record the last point */
		ctx->remote_rdma_ring_mrs_offset[target_node] = real_size;
	else
		ctx->remote_rdma_ring_mrs_offset[target_node] += real_size;

	/* Trace back to the real starting point */
	tar_offset_start = ctx->remote_rdma_ring_mrs_offset[target_node] - real_size;
	spin_unlock(&ctx->remote_imm_offset_lock[target_node]);

	/* Make sure we do not write beyond lastack */
	while (1) {
		last_ack = ctx->remote_last_ack_index[target_node];
		if (tar_offset_start < last_ack && tar_offset_start + real_size > last_ack)
			schedule();
		else
			break;
	}

	remote_mr = &(ctx->remote_rdma_ring_mrs[target_node]);

	connection_id = fit_get_connection_by_atomic_number(ctx, target_node, LOW_PRIORITY);

	imm_data = IMM_SEND_REPLY_SEND | tar_offset_start;

	msg_header.reply_addr = 0;
	msg_header.reply_rkey = 0;
	msg_header.reply_indicator_index = -1;
	msg_header.source_node_id = ctx->node_id;
	msg_header.size = size;
	remote_addr = remote_mr->addr;
	remote_rkey = remote_mr->rkey;

	fit_debug("send imm-%x addr-%x rkey-%x oaddr-%x orkey-%x\n",
		imm_data, remote_addr, remote_rkey, msg_header.reply_addr, msg_header.reply_rkey);

	/* for send reply, no need to poll the send now, since we have reply already */
	ret = fit_send_message_with_rdma_write_with_imm_request(ctx, connection_id, remote_rkey,
			(uintptr_t)remote_addr, addr, size, tar_offset_start, imm_data,
			FIT_SEND_MESSAGE_HEADER_AND_IMM, &msg_header, 0);

	return ret;
}

/*
 * This is one major function, it is used by ibapi_send_reply().
 * This function is blocking, it uses busy polling to get reply.
 *
 * Return:
 * Negative values on failues
 * Positive values indicate the reply message length
 */
int fit_send_reply_with_rdma_write_with_imm(ppc *ctx, int target_node, void *addr,
					       int size, void *ret_addr, int max_ret_size,
					       int userspace_flag, int if_use_ret_phys_addr,
					       unsigned long timeout_sec, void *caller)
{
	int tar_offset_start;
	int connection_id;
	int reply_indicator_index;
	int imm_data;
	int real_size;
	void *remote_addr;
	uint32_t remote_rkey;
	struct fit_ibv_mr *remote_mr;
	struct imm_message_metadata msg_header;
	int last_ack;
	unsigned long start_time;
	int reply_length;

	int local_reply_ready_checker = SEND_REPLY_WAIT;

	if (unlikely(!addr)) {
		fit_err("BUG: NULL addr. Caller: %pS", caller);
		return -EINVAL;
	}

	real_size = size + sizeof(struct imm_message_metadata);
	if (unlikely(real_size > IMM_MAX_SIZE)) {
		fit_err("Size %d + header > %d", size, IMM_MAX_SIZE);
		return -EINVAL;
	}

	spin_lock(&ctx->remote_imm_offset_lock[target_node]);
	/* If hits the end of ring, write start from 0 directly */
	if (ctx->remote_rdma_ring_mrs_offset[target_node] + real_size >= RDMA_RING_SIZE)
		/* Record the last point */
		ctx->remote_rdma_ring_mrs_offset[target_node] = real_size;
	else
		ctx->remote_rdma_ring_mrs_offset[target_node] += real_size;

	/* Trace back to the real starting point */
	tar_offset_start = ctx->remote_rdma_ring_mrs_offset[target_node] - real_size;
	spin_unlock(&ctx->remote_imm_offset_lock[target_node]);

	/* Make sure we do not write beyond lastack */
	while (1) {
		last_ack = ctx->remote_last_ack_index[target_node];
		if (tar_offset_start < last_ack && tar_offset_start + real_size > last_ack)
			schedule();
		else
			break;
	}

	remote_mr = &(ctx->remote_rdma_ring_mrs[target_node]);

	connection_id = fit_get_connection_by_atomic_number(ctx, target_node, LOW_PRIORITY);

	reply_indicator_index = alloc_index_and_set_reply_indicator(ctx, &local_reply_ready_checker);

	imm_data = IMM_SEND_REPLY_SEND | tar_offset_start;

	if (if_use_ret_phys_addr == 1)
		msg_header.reply_addr = fit_ib_reg_mr_addr_phys(ctx, ret_addr, max_ret_size);
	else
		msg_header.reply_addr = fit_ib_reg_mr_addr(ctx, ret_addr, max_ret_size);

	msg_header.reply_rkey = ctx->proc->rkey;
	msg_header.reply_indicator_index = reply_indicator_index;
	msg_header.source_node_id = ctx->node_id;
	msg_header.size = size;
	remote_addr = remote_mr->addr;
	remote_rkey = remote_mr->rkey;

	fit_debug("send imm-%x addr-%x rkey-%x oaddr-%x orkey-%x\n",
		imm_data, remote_addr, remote_rkey, msg_header.reply_addr, msg_header.reply_rkey);

	/* for send reply, no need to poll the send now, since we have reply already */
	fit_send_message_with_rdma_write_with_imm_request(ctx, connection_id, remote_rkey,
			(uintptr_t)remote_addr, addr, size, tar_offset_start, imm_data,
			FIT_SEND_MESSAGE_HEADER_AND_IMM, &msg_header, 0);

	/*
	 * Default model
	 *
	 * And we don't want to stuck here forever.
	 * So we add timeout checking here.
	 *
	 * Side note:
	 * This is where make our network requests all synchronous.
	 * If we want to change the behaviour, we need to change here.
	 */
	/* Caller does not specify an timeout, use the maximum */
	if (timeout_sec == 0)
		timeout_sec = FIT_MAX_TIMEOUT_SEC;

	if (timeout_sec > FIT_MAX_TIMEOUT_SEC)
		timeout_sec = FIT_MAX_TIMEOUT_SEC;

	start_time = jiffies;

	/*
	 * The local_reply_ready_checker will be set by
	 * recv_cq polling thread, when it gets the reply.
	 */
	while (local_reply_ready_checker == SEND_REPLY_WAIT) {
		cpu_relax();
		if (unlikely(time_after(jiffies, start_time + timeout_sec * HZ))) {
			pr_warn("ibapi_send_reply() CPU:%d PID:%d timeout (%u ms), caller: %pS\n",
				smp_processor_id(), current->pid,
				jiffies_to_msecs(jiffies - start_time), caller);
			print_pcache_events();
			print_profile_points();
			dump_ib_stats();
			return -ETIMEDOUT;
		}
	}
	free_reply_indicator(ctx, reply_indicator_index);
	reply_length = local_reply_ready_checker;

	if (unlikely(reply_length < 0)) {
		fit_err("connection-%d inbox-%d reply-length-%d",
			connection_id, reply_indicator_index, reply_length);
	}
	return reply_length;
}

/*
 * send data and reply with extra bits
 * Return:
 * Negative values on failues
 * Positive values indicate the reply message length
 */
int fit_send_reply_with_rdma_write_with_imm_reply_extra_bits(ppc *ctx, int target_node, void *addr,
					       int size, void *ret_addr, int max_ret_size, int *ret_private_bits,
					       int userspace_flag, int if_use_ret_phys_addr,
					       unsigned long timeout_sec, void *caller)
{
	int tar_offset_start;
	int connection_id;
	int reply_indicator_index;
	int imm_data;
	int local_reply_ready_checker = SEND_REPLY_WAIT;
	int real_size;
	void *remote_addr;
	uint32_t remote_rkey;
	struct fit_ibv_mr *remote_mr;
	struct imm_message_metadata msg_header;
	int last_ack;
	unsigned long start_time;
	int reply_length;

	real_size = size + sizeof(struct imm_message_metadata);
	if(real_size > IMM_MAX_SIZE) {
		printk(KERN_CRIT "%s: message size %d + header %d is larger than max size %d\n",
			__func__, size, real_size, IMM_MAX_SIZE);
		return -1;
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

	/* make sure we do not write beyond lastack */
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

	reply_indicator_index = alloc_index_and_set_reply_indicator(ctx, &local_reply_ready_checker);

	imm_data = IMM_SEND_REPLY_SEND | tar_offset_start;

	if (if_use_ret_phys_addr == 1)
		msg_header.reply_addr = fit_ib_reg_mr_addr_phys(ctx, ret_addr, max_ret_size);
	else
		msg_header.reply_addr = fit_ib_reg_mr_addr(ctx, ret_addr, max_ret_size);

	msg_header.reply_rkey = ctx->proc->rkey;
	msg_header.reply_indicator_index = reply_indicator_index;
	msg_header.source_node_id = ctx->node_id;
	msg_header.size = size;
	remote_addr = remote_mr->addr;
	remote_rkey = remote_mr->rkey;

	fit_debug("send imm-%x addr-%x rkey-%x oaddr-%x orkey-%x\n",
		imm_data, remote_addr, remote_rkey, msg_header.reply_addr, msg_header.reply_rkey);

#ifdef SCHEDULE_MODEL
	ctx->thread_waiting_for_reply[reply_indicator_index] = get_current();
	set_current_state(TASK_INTERRUPTIBLE);
#endif
	/* for send reply, no need to poll the send now, since we have reply already */
	fit_send_message_with_rdma_write_with_imm_request(ctx, connection_id, remote_rkey,
			(uintptr_t)remote_addr, addr, size, tar_offset_start, imm_data,
			FIT_SEND_MESSAGE_HEADER_AND_IMM, &msg_header, 0);

#ifdef SCHEDULE_MODEL
	schedule();
	set_current_state(TASK_RUNNING);
#endif

#ifdef CPURELAX_MODEL
	/* Caller does not specify timeout, use the maximum */
	if (timeout_sec == 0)
		timeout_sec = FIT_MAX_TIMEOUT_SEC;

	if (timeout_sec > FIT_MAX_TIMEOUT_SEC)
		timeout_sec = FIT_MAX_TIMEOUT_SEC;

	start_time = jiffies;

	/*
	 * the local_reply_ready_checker will be set by the polling thread
	 * when it gets the reply
	 */
	while (local_reply_ready_checker == SEND_REPLY_WAIT) {
		cpu_relax();
		if (unlikely(time_after(jiffies, start_time + timeout_sec * HZ))) {
			pr_warn("ibapi_send_reply() polling timeout (%u ms), caller: %pS\n",
				jiffies_to_msecs(jiffies - start_time), caller);
			return -ETIMEDOUT;
		}
	}
	free_reply_indicator(ctx, reply_indicator_index);
	reply_length = local_reply_ready_checker >> REPLY_PRIVATE_BITS_CNT;
	*ret_private_bits = local_reply_ready_checker & 0xff;
#endif

#ifdef ADAPTIVE_MODEL
	//If size is small, it should do busy wait here, or the waiting time is too long, it should jump to sleep queue
	if(size<=IMM_SEND_SLEEP_SIZE_THRESHOLD)
	{
		unsigned long j0,j1;
		j0 = jiffies;
		j1 = j0 + usecs_to_jiffies(IMM_SEND_SLEEP_TIME_THRESHOLD);
		while(local_reply_ready_checker==SEND_REPLY_WAIT && time_before(jiffies, j1))
			//cpu_relax();
			schedule();
	}

	/*
	 * check if reply is ready
	 * If the size is small and time is short,
	 * it should get local_reply_ready_checker from the above if loop;
	 * Else do wait here.
	*/
	if (local_reply_ready_checker == SEND_REPLY_WAIT)
	{
		while (local_reply_ready_checker == SEND_REPLY_WAIT)
		{
			if (wait_event_interruptible_timeout(ctx->imm_inbox_block_queue[reply_indicator_index],
					local_reply_ready_checker != SEND_REPLY_WAIT, msecs_to_jiffies(3000)))
				break;
		}
	}
	reply_length = local_reply_ready_checker >> REPLY_PRIVATE_BITS_CNT;
	*ret_private_bits = local_reply_ready_checker & 0xff;
#endif

	if (reply_length < 0)
	{
		printk(KERN_CRIT "%s: [significant error] send-reply-imm fail with connection-%d inbox-%d reply-length-%d\n",
				__func__, connection_id, reply_indicator_index, reply_length);
	}

	return reply_length;
}

/**
 * fit_multicast_send_reply - issue a RDMA request with several sge request - mainly used for multicast in kernel
 * @ctx: fit context
 * @num_nodes: number of multicast node
 * @target_node: target node array
 * @sglist: message array to be sent to the nodes
 * @output_msg: array of reply message buffer
 */
int fit_multicast_send_reply(ppc *ctx, int num_nodes, int *target_node,
						struct fit_sglist *sglist, struct fit_sglist *output_msg,
						int max_ret_size, int userspace_flag, int if_use_ret_phys_addr,
						unsigned long timeout_sec, void *caller)
{
	int tar_offset_start;
	int connection_id;
	int reply_indicator_index;
	int imm_data;
	int *local_reply_ready_checker;
	int real_size;
	void *remote_addr;
	uint32_t remote_rkey;
	struct fit_ibv_mr *remote_mr;
	struct imm_message_metadata *msg_header;
	int last_ack;
	unsigned long start_time;
        int ret = 0;

        int i;
	//struct ib_device *ibd = (struct ib_device *)ctx->context;

        if(!sglist || !target_node || !output_msg || !num_nodes)
        {
		printk(KERN_CRIT "%s: null input target_node %p input list %p output_msg %p\n",
				__func__, target_node, sglist, output_msg);
                return -2;
        }

        local_reply_ready_checker = kmalloc(sizeof(int) * num_nodes, GFP_KERNEL);
        msg_header = kmalloc(sizeof(struct imm_message_metadata) * num_nodes, GFP_KERNEL);

        for (i = 0; i < num_nodes; i++)
        {
                local_reply_ready_checker[i] = SEND_REPLY_WAIT;
                if (target_node[i] <= 0)
                {
                        printk(KERN_CRIT "%s: target %d node %d\n",
				__func__, i, target_node[i]);
                        ret = -2;
			goto out;
                }
                real_size = sglist[i].len + sizeof(struct imm_message_metadata);
	        if(real_size > IMM_MAX_SIZE)
		{
			printk(KERN_CRIT "%s: target %d, message size %d + header is larger than max size %d\n", __func__, i, real_size, IMM_MAX_SIZE);
			ret = -1;
			goto out;
		}

		spin_lock(&ctx->remote_imm_offset_lock[target_node[i]]);
		if(ctx->remote_rdma_ring_mrs_offset[target_node[i]] + real_size >= RDMA_RING_SIZE)//If hits the end of ring, write start from 0 directly
			ctx->remote_rdma_ring_mrs_offset[target_node[i]] = real_size;//Record the last point
		else
			ctx->remote_rdma_ring_mrs_offset[target_node[i]] += real_size;
		tar_offset_start = ctx->remote_rdma_ring_mrs_offset[target_node[i]] - real_size;//Trace back to the real starting point
		spin_unlock(&ctx->remote_imm_offset_lock[target_node[i]]);

		/* make sure we do not write beyond lastack */
		while(1)
		{
			last_ack = ctx->remote_last_ack_index[target_node[i]];
			if(tar_offset_start < last_ack && tar_offset_start + real_size > last_ack)
				schedule();
			else
				break;
		}

		remote_mr = &(ctx->remote_rdma_ring_mrs[target_node[i]]);
		connection_id = fit_get_connection_by_atomic_number(ctx, target_node[i], LOW_PRIORITY);
		reply_indicator_index = alloc_index_and_set_reply_indicator(ctx, &local_reply_ready_checker[i]);
                imm_data = IMM_SEND_REPLY_SEND | tar_offset_start;

		if (if_use_ret_phys_addr == 1)
			msg_header[i].reply_addr = fit_ib_reg_mr_addr_phys(ctx, output_msg[i].addr, max_ret_size);
		else
			msg_header[i].reply_addr = fit_ib_reg_mr_addr(ctx, output_msg[i].addr, max_ret_size);
		msg_header[i].reply_rkey = ctx->proc->rkey;
		msg_header[i].reply_indicator_index = reply_indicator_index;
		msg_header[i].source_node_id = ctx->node_id;
		msg_header[i].size = real_size - sizeof(struct imm_message_metadata);
		remote_addr = remote_mr->addr;
		remote_rkey = remote_mr->rkey;

		fit_debug("send imm-%x addr-%lx rkey-%x addr-%lx rkey-%x\n",
				imm_data, (unsigned long)remote_addr, remote_rkey, (unsigned long)msg_header[i].reply_addr, msg_header[i].reply_rkey);
		/* for send reply, no need to poll the send now, since we have reply already */
		fit_send_message_with_rdma_write_with_imm_request(ctx, connection_id, remote_rkey,
				(uintptr_t)remote_addr, sglist[i].addr, sglist[i].len, tar_offset_start, imm_data,
				FIT_SEND_MESSAGE_HEADER_AND_IMM, &msg_header[i], 0);
	}

	/* Caller does not specify an timeout, use the maximum */
	if (timeout_sec == 0)
		timeout_sec = FIT_MAX_TIMEOUT_SEC;

	if (timeout_sec > FIT_MAX_TIMEOUT_SEC)
		timeout_sec = FIT_MAX_TIMEOUT_SEC;

	start_time = jiffies;

	for (i = 0; i < num_nodes; i++)
	{
		while(local_reply_ready_checker[i]==SEND_REPLY_WAIT)
		{
			cpu_relax();
			if (unlikely(time_after(jiffies, start_time + timeout_sec * HZ))) {
				pr_warn("%s CPU:%d PID:%d timeout (%u ms), caller: %pS\n",
						__func__, smp_processor_id(), current->pid,
						jiffies_to_msecs(jiffies - start_time), caller);
				return -ETIMEDOUT;
			}
		}
		if(local_reply_ready_checker[i] < 0)
		{
			printk(KERN_CRIT "%s: [significant error] send-reply-imm fail with target %d node %d status-%d\n",
					__func__, i, target_node[i], local_reply_ready_checker[i]);
		}
		else
		{
			ret++;
		}
		output_msg[i].len = local_reply_ready_checker[i];
	}

	if (1) {
		panic("If used, patch the usage reply_indicator. "
		      "Similar to send_reply part.");
	}

out:
	kfree(local_reply_ready_checker);
	kfree(msg_header);

	return ret;
}

int fit_send_message_sge(ppc *ctx, int connection_id, int type, void *addr,
			 int size, uint64_t reply_addr, uint64_t reply_indicator_index,
			 int priority)
{
	struct ib_send_wr wr, *bad_wr = NULL;
	struct ib_sge sge[2];
	int ret;
	int ne, i;
	struct ib_wc wc[2];
	struct ibapi_header msg_header;
	void *msg_header_addr;
	unsigned long start_ns;

	fit_debug("conn %d addr %p size %d sendcq %p type %d\n",
		connection_id, addr, size, ctx->send_cq[connection_id], type);

	memset(&wr, 0, sizeof(wr));
	memset(sge, 0, sizeof(sge));

	wr.wr_id = type;
	wr.opcode = IB_WR_SEND;
	wr.sg_list = sge;
	wr.num_sge = 2;
	wr.send_flags = IB_SEND_SIGNALED;

	fit_setup_ibapi_header(ctx->node_id, reply_addr, reply_indicator_index, size, priority, type, &msg_header);
	msg_header_addr = (void *)fit_ib_reg_mr_addr(ctx, &msg_header, sizeof(struct ibapi_header));
	sge[0].addr = (uintptr_t)msg_header_addr;
	sge[0].length = sizeof(struct ibapi_header);
	sge[0].lkey = ctx->proc->lkey;
	sge[1].addr = (uintptr_t)fit_ib_reg_mr_addr(ctx, addr, size);
	sge[1].length = size;
	sge[1].lkey = ctx->proc->lkey;

	ret = ib_post_send(ctx->qp[connection_id], &wr, &bad_wr);
	if (ret) {
		fit_err("Fail to post. ret=%d", ret);
		return ret;
	}

	start_ns = sched_clock();
	do {
		ne = ib_poll_cq(ctx->send_cq[connection_id], 1, wc);
		if (ne < 0) {
			fit_err("Fail to poll CQ. ret=%d", ne);
			return ne;
		}

		if (unlikely(sched_clock() - start_ns > FIT_POLL_CQ_TIMEOUT_NS)) {
			pr_info_once("\n"
				"*****\n"
				"***** Fail to to get the CQE from send_cq (%p) after %ld seconds!\n"
				"***** CPU: %d connection_id: %d dest node: %d\n"
				"*****\n",
				ctx->send_cq[connection_id],
				FIT_POLL_CQ_TIMEOUT_NS/NSEC_PER_SEC,
				smp_processor_id(),
				connection_id, connection_id / NUM_PARALLEL_CONNECTION);
			WARN_ON_ONCE(1);
			return -ETIMEDOUT;
		}
	} while (ne < 1);

	for (i = 0; i < ne; i++) {
		if (wc[i].status != IB_WC_SUCCESS) {
			fit_err("wc.status: %s", ib_wc_status_msg(wc[i].status));
			return -EIO;
		}
	}
	return 0;
}

static int send_rdma_ring_mr_to_other_nodes(ppc *ctx)
{
	int i;
	int connection_id;
	char *msg;
	int ret;
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

		fit_debug("send ringmr addr %p lkey %lx rkey %lx sockaddr %p conn %d node %d\n",
				ctx->local_rdma_ring_mrs[i].addr,
				ctx->local_rdma_ring_mrs[i].lkey,
				ctx->local_rdma_ring_mrs[i].rkey,
				ctx->local_sock_rdma_ring_mrs[i], connection_id, i);
#else
		connection_id = NUM_PARALLEL_CONNECTION * i;

		fit_debug("send ringmr addr %p lkey %lx rkey %lx conn %d node %d\n",
				ctx->local_rdma_ring_mrs[i].addr,
				ctx->local_rdma_ring_mrs[i].lkey,
				ctx->local_rdma_ring_mrs[i].rkey,
				connection_id, i);
#endif
		ret = fit_send_message_sge(ctx, connection_id, MSG_SEND_RDMA_RING_MR, msg, size, 0, 0, LOW_PRIORITY);
	}
	kfree(msg);

	return ret;
}

ppc *fit_establish_conn(struct ib_device *ib_dev, int ib_port, int mynodeid)
{
	int     i;
	ppc *ctx;
	struct fit_ibv_mr *ret_mr;
	struct thread_pass_struct *info;
	int num_connected_nodes = 0;
	int	size = 8192;
	int	rx_depth = RECV_DEPTH;
	int	ret;

	mtu = IB_MTU_2048;
	sl = 0;

	ctx = kzalloc(sizeof(struct lego_context), GFP_KERNEL);
	if (!ctx)
		return NULL;

	/*
	 * This is another waiting point..
	 * We need to wait for the port to change state.
	 * Seems related to MAD and interrupt events.
	 */
retry:
	ret = ib_query_port(ib_dev, ib_port, &ctx->portinfo);
	pr_info("%s() after query CPU%d port: %d LID: %d state: %d\n",
		__func__, smp_processor_id(), ib_port,
		ctx->portinfo.lid, ctx->portinfo.state);

	if (ret < 0) {
		pr_err("Fail to query port\n");
		return NULL;
	}

	if (!ctx->portinfo.lid ||
	    ctx->portinfo.state != IB_PORT_ACTIVE) {
#if 1
		mdelay(1000);
		pr_info("%s() CPU%d port: %d LID: %d state: %d\n",
			__func__, smp_processor_id(), ib_port,
			ctx->portinfo.lid, ctx->portinfo.state);
#endif
		goto retry;
	}
	pr_info("Query returned LID: %d\n", ctx->portinfo.lid);

	/*
	 * Sanity Check...
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
		hlt();
	}

	/* This function will create a lot stuff including CQ, QP */
	ctx = fit_init_ctx(ctx, size, rx_depth, ib_port, ib_dev, mynodeid);
	if (!ctx) {
		pr_err("Fail to init ctx\n");
		return NULL;
	}

	//Initialize waiting_queue/request list related items
	INIT_LIST_HEAD(&(request_list.list));

	info = kmalloc(sizeof(*info) * NUM_POLLING_THREADS, GFP_KERNEL);
	if (!info)
		return NULL;

	for (i = 0; i < NUM_POLLING_THREADS; i++) {
		info[i].recvcq_id = i;
		info[i].ctx = ctx;
		info[i].target_cq = ctx->cq[i];
		kthread_run(fit_poll_recv_cq, &info[i], "FIT_RecvCQ-%d", i);
	}

#ifdef CONFIG_SOCKET_SYSCALL
	if (1) {
		struct thread_pass_struct sock_thread_pass_poll_cq;

		sock_thread_pass_poll_cq.ctx = ctx;
		sock_thread_pass_poll_cq.target_cq = ctx->sock_recv_cq;
		kthread_run(sock_poll_cq, &sock_thread_pass_poll_cq, "fit_sockrecvpollcq");
	}
#endif

	kthread_run(waiting_queue_handler, ctx, "FIT_WQ_Handler");

	/*
	 * Allocate and register local RDMA-IMM rings for all nodes
	 */
	ctx->local_rdma_recv_rings = kmalloc(MAX_NODE * sizeof(void *), GFP_KERNEL);
	ctx->local_rdma_ring_mrs = kmalloc(MAX_NODE * sizeof(struct fit_ibv_mr), GFP_KERNEL);
	for(i=0; i<MAX_NODE; i++)
	{
		ctx->local_rdma_recv_rings[i] = fit_alloc_memory_for_mr(IMM_PORT_CACHE_SIZE);
		ret_mr = fit_ib_reg_mr(ctx, ctx->local_rdma_recv_rings[i], IMM_RING_SIZE,
				IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ);
		memcpy(&ctx->local_rdma_ring_mrs[i], ret_mr, sizeof(struct fit_ibv_mr));
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

	ctx->node_id = mynodeid;
	for (i = 0; i < MAX_NODE; i++) {
		if (i == mynodeid)
			continue;
		fit_add_newnode(ctx, i, mynodeid);
		num_connected_nodes++;
	}

	/*
	 * TODO:
	 * change this to contiguously sending info until we got all
	 * also add necessary info to track what've got.
	 * This timeout is just too fragile.
	 */
#ifdef CONFIG_FIT_INITIAL_SLEEP_TIMEOUT
	for (i = 0; i < CONFIG_FIT_INITIAL_SLEEP_TIMEOUT * 1000; i++) {
		udelay(1000);
	}
#else
	/* Default is 30 s */
	for (i = 0; i < 30 * 1000; i++) {
		udelay(1000);
	}
#endif
	send_rdma_ring_mr_to_other_nodes(ctx);

	pr_debug("Please wait other nodes to join ...\n");
	while (nr_joined_nodes < ctx->num_node - 1)
		schedule();
	return ctx;
}
