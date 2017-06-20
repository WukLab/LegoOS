#include <lego/sched.h>
#include <lego/slab.h>
#include <lego/init.h>
#include <lego/mm.h>
#include <lego/types.h>
#include <lego/spinlock.h>
#include <asm/tlbflush.h>
#include <lego/list.h>
#include <lego/string.h>
#include <lego/jiffies.h>
#include <lego/atomic.h>
#include <rdma/ib_verbs.h>
#include <lego/types.h>
#include <lego/net.h>

#define TOTAL_CONNECTIONS 1
#define MAX_REQ_SIZE 4096*2

atomic_t global_reqid;

enum {
	PINGPONG_RECV_WRID = 1,
	PINGPONG_SEND_WRID = 2,
};

static int page_size;

struct pingpong_context {
	struct ib_device	*context;
	struct ib_comp_channel *channel;
	struct ib_pd		*pd;
	struct ib_mr		*mr;
	struct ib_cq		*cq;
	struct ib_qp		*qp;
	char			*buf;
	int			 size;
	int			 send_flags;
	int			 rx_depth;
	int			 pending;
	struct ib_port_attr     portinfo;
	u64			uaddr;
};

struct pingpong_dest {
	int lid;
	int qpn;
	int psn;
	union ib_gid gid;
};

static void poll_cq(struct ib_cq *cq, void *cq_context);

//static struct ib_device *ibv_add_port(struct pingpong_context *device, u8 port);
static void ibv_add_one(struct ib_device *device);
static void ibv_release_dev(struct device *dev);
static void ibv_remove_one(struct ib_device *device);


static struct ib_client ibv_client = {
	.name   = "ibv_server",
	.add    = ibv_add_one,
	.remove = ibv_remove_one
};

struct ib_device *ib_dev;
struct ib_pd *ctx_pd;
struct pingpong_context **ctx;

static void poll_cq(struct ib_cq *cq, void *cq_context)
{
  struct ib_wc wc;
  int ret;
  while (1) {
    ret = ib_req_notify_cq(cq, 0);
	printk(KERN_ALERT "ib_req_notify_cq returned %d\n", ret);
    while (ib_poll_cq(cq, 1, &wc)){
    }
  }
}

static int pp_connect_ctx(int ctxid, int port, int my_psn,
			  enum ib_mtu mtu, int sl,
			  int sgid_idx)
{
	struct ib_qp_attr attr = {
		.qp_state		= IB_QPS_RTR,
		.path_mtu		= mtu,
		.dest_qp_num		= 72, //dest->qpn,
		.rq_psn			= 1, //dest->psn,
		.max_dest_rd_atomic	= 1,
		.min_rnr_timer		= 12,
		.ah_attr		= {
			.dlid		= 7, //dest->lid,
			.sl		= sl,
			.src_path_bits	= 0,
			.port_num	= port
		}
	};


	if (ib_modify_qp(ctx[ctxid]->qp, &attr,
			  IB_QP_STATE              |
			  IB_QP_AV                 |
			  IB_QP_PATH_MTU           |
			  IB_QP_DEST_QPN           |
			  IB_QP_RQ_PSN             |
			  IB_QP_MAX_DEST_RD_ATOMIC |
			  IB_QP_MIN_RNR_TIMER)) {
		printk(KERN_ALERT "Failed to modify QP to RTR\n");
		return 1;
	}

	attr.qp_state	    = IB_QPS_RTS;
	attr.timeout	    = 21;
	attr.retry_cnt	    = 7;
	attr.rnr_retry	    = 7;
	attr.sq_psn	    = my_psn;
	attr.max_rd_atomic  = 1;
	if (ib_modify_qp(ctx[ctxid]->qp, &attr,
			  IB_QP_STATE              |
			  IB_QP_TIMEOUT            |
			  IB_QP_RETRY_CNT          |
			  IB_QP_RNR_RETRY          |
			  IB_QP_SQ_PSN             |
			  IB_QP_MAX_QP_RD_ATOMIC)) {
		printk(KERN_ALERT "Failed to modify QP to RTS\n");
		return 1;
	}

	pr_debug("%s finished\n", __func__);
	return 0;
}

static int pp_init_ctx(int ctxid, int size, int rx_depth, int port, int use_event)
{
	struct page *pp;

	ctx[ctxid]->size       = size;
	ctx[ctxid]->send_flags = IB_SEND_SIGNALED;
	ctx[ctxid]->rx_depth   = rx_depth;

        pp = alloc_pages(GFP_KERNEL, 2);
        ctx[ctxid]->buf = (char *)page_address(pp);

        if (!ctx[ctxid]->buf) {
                printk(KERN_ALERT "Couldn't allocate work buf.\n");
                goto clean_ctx;
        }

        memset(ctx[ctxid]->buf, 0x7b, size);

        ctx[ctxid]->context = ib_dev;
        if (!ctx[ctxid]->context) {
                printk(KERN_ALERT "Couldn't get context for ib_device\n");
                goto clean_buffer;
        }

	ctx[ctxid]->channel = NULL;

	ctx[ctxid]->pd = ib_alloc_pd(ib_dev);
	if (!ctx[ctxid]->pd) {
		printk(KERN_ALERT "Couldn't allocate PD\n");
	}
	printk(KERN_CRIT "init ctxid %d pd %p device %p ib_dev %p context %p\n", ctxid, ctx[ctxid]->pd, ctx[ctxid]->pd->device, ib_dev, ctx[ctxid]->context);
	ctx[ctxid]->mr = ib_get_dma_mr(ctx[ctxid]->pd, IB_ACCESS_LOCAL_WRITE |IB_ACCESS_REMOTE_WRITE| IB_ACCESS_REMOTE_READ);
	if (!ctx[ctxid]->mr) {
		printk(KERN_ALERT "Couldn't register MR\n");
		goto clean_pd;
	}
	else
		pr_debug("got mr %p\n", ctx[ctxid]->mr);

        ctx[ctxid]->uaddr = ib_dma_map_single(ib_dev, ctx[ctxid]->buf, size, DMA_BIDIRECTIONAL);
        printk(KERN_ALERT "mr.lkey: %x\n", ctx[ctxid]->mr->lkey);

	ctx[ctxid]->cq = ib_create_cq(ctx[ctxid]->context, NULL, NULL, NULL, rx_depth+1, 0);
	if (!ctx[ctxid]->cq) {
		printk(KERN_ALERT "Couldn't create CQ\n");
		goto clean_mr;
	}
	pr_debug("%s created cq %p\n", __func__, ctx[ctxid]->cq);

	{
		struct ib_qp_attr attr;
		struct ib_qp_init_attr init_attr = {
			.send_cq = ctx[ctxid]->cq,
			.recv_cq = ctx[ctxid]->cq,
			.cap     = {
				.max_send_wr  = 1,
				.max_recv_wr  = rx_depth,
				.max_send_sge = 10,
				.max_recv_sge = 1
			},
			.qp_type = IB_QPT_RC
		};

		ctx[ctxid]->qp = ib_create_qp(ctx[ctxid]->pd, &init_attr);
		if (!ctx[ctxid]->qp)  {
			printk(KERN_ALERT "Couldn't create QP\n");
			goto clean_cq;
		}

		ib_query_qp(ctx[ctxid]->qp, &attr, IB_QP_CAP, &init_attr);
		if (init_attr.cap.max_inline_data >= size) {
			ctx[ctxid]->send_flags |= IB_SEND_INLINE;
		}
	}

	{
		struct ib_qp_attr attr = {
			.qp_state        = IB_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = port,
			.qp_access_flags = 0
		};

		if (ib_modify_qp(ctx[ctxid]->qp, &attr,
				  IB_QP_STATE              |
				  IB_QP_PKEY_INDEX         |
				  IB_QP_PORT               |
				  IB_QP_ACCESS_FLAGS)) {
			printk(KERN_ALERT "Failed to modify QP to INIT\n");
			goto clean_qp;
		}
	}

	return 1;

clean_qp:
	ib_destroy_qp(ctx[ctxid]->qp);

clean_cq:
	ib_destroy_cq(ctx[ctxid]->cq);

clean_mr:
	ib_dereg_mr(ctx[ctxid]->mr);

clean_pd:
	ib_dealloc_pd(ctx[ctxid]->pd);

clean_buffer:
	kfree(ctx[ctxid]->buf);

clean_ctx:
	kfree(ctx);

	return NULL;
}

int pp_close_ctx(int ctxid)
{
	if (ib_destroy_qp(ctx[ctxid]->qp)) {
		printk(KERN_ALERT "Couldn't destroy QP\n");
		return 1;
	}

	if (ib_destroy_cq(ctx[ctxid]->cq)) {
		printk(KERN_ALERT "Couldn't destroy CQ\n");
		return 1;
	}

	if (ib_dereg_mr(ctx[ctxid]->mr)) {
		printk(KERN_ALERT "Couldn't deregister MR\n");
		return 1;
	}

	if (ib_dealloc_pd(ctx[ctxid]->pd)) {
		printk(KERN_ALERT "Couldn't deallocate PD\n");
		return 1;
	}

	kfree(ctx);

	return 0;
}

static int pp_post_recv(int ctxid, int n)
{
	struct ib_sge list = {
		.addr	= ctx[ctxid]->uaddr, //(uintptr_t) ctx[ctxid]->buf,
		.length = ctx[ctxid]->size,
		.lkey	= ctx[ctxid]->mr->lkey
	};
	struct ib_recv_wr wr = {
		.wr_id	    = PINGPONG_RECV_WRID,
		.sg_list    = &list,
		.num_sge    = 1,
	};
	struct ib_recv_wr *bad_wr;
	int i;

	for (i = 0; i < n; ++i)
		if (ib_post_recv(ctx[ctxid]->qp, &wr, &bad_wr))
			break;

	return i;
}

static int pp_post_recv1(int ctxid)
{
	struct ib_sge list = {
		.addr	= ctx[ctxid]->uaddr, //(uintptr_t) ctx[ctxid]->buf,
		.length = ctx[ctxid]->size,
		.lkey	= ctx[ctxid]->mr->lkey
	};
	struct ib_recv_wr wr = {
		.wr_id	    = PINGPONG_RECV_WRID,
		.sg_list    = &list,
		.num_sge    = 1,
	};
	struct ib_recv_wr *bad_wr;
	int i, ret;

	ret = ib_post_recv(ctx[ctxid]->qp, &wr, &bad_wr);

	return ret;
}

static int pp_post_send(int ctxid)
{
	struct ib_sge list = {
		.addr	= ctx[ctxid]->uaddr,//(uintptr_t) ctx[ctxid]->buf,
		.length = ctx[ctxid]->size,
		.lkey	= ctx[ctxid]->mr->lkey
	};
	struct ib_send_wr wr = {
		.wr_id	    = PINGPONG_SEND_WRID,
		.sg_list    = &list,
		.num_sge    = 1,
		.opcode     = IB_WR_SEND,
		.send_flags = ctx[ctxid]->send_flags,
	};
	struct ib_send_wr *bad_wr;

	return ib_post_send(ctx[ctxid]->qp, &wr, &bad_wr);
}

static int pp_post_send1(int ctxid, struct ib_sge *list, int num_sge)
{
	struct ib_send_wr wr = {
		.wr_id	    = PINGPONG_SEND_WRID,
		.sg_list    = list,
		.num_sge    = num_sge,
		.opcode     = IB_WR_SEND,
		.send_flags = ctx[ctxid]->send_flags,
	};
	struct ib_send_wr *bad_wr;

	return ib_post_send(ctx[ctxid]->qp, &wr, &bad_wr);
}

int send_msg(int ctxid, void *data, int len)
{
	unsigned long reqid;
	int ret = 0;
	int i;
	struct ib_sge sge_list[4];
	u64 uaddr;
	int size;

#if 0
        uaddr = ib_dma_map_single(ib_dev, (void*)&phys_addr, size, DMA_BIDIRECTIONAL);
	if (ret = ib_dma_mapping_error(ib_dev, uaddr)) {
		printk(KERN_CRIT "dma_map_single error %d uaddr %llx\n", ret, uaddr);
	}
#endif
	//testing
	if (data == NULL) {
		ctx[ctxid]->buf[0] = 'a';
		ctx[ctxid]->buf[1] = 'a';
		ctx[ctxid]->buf[2] = 'a';
		ctx[ctxid]->buf[3] = 'a';
		sge_list[0].addr = ctx[ctxid]->uaddr; //uaddr;
		sge_list[0].length = 4; //len;
		sge_list[0].lkey = ctx[ctxid]->mr->lkey; 
	}

resend_req:

	ret = pp_post_send1(ctxid, sge_list, 1);
	printk(KERN_CRIT "%s after postsend ret %d\n", __func__, ret);
	if (ret != 0) {
		printk(KERN_CRIT "replicate_pages failed at send ret %d\n", ret);
//		goto resend_req;
	}

	ctx[ctxid]->pending = PINGPONG_RECV_WRID;
	struct ib_wc wc[2];
	int ne;
	do {
		ne = ib_poll_cq(ctx[ctxid]->cq, 1, wc);
		if (ne < 0) {
			printk(KERN_ALERT "poll CQ failed %d\n", ne);
			return 1;
		}

	} while (ne < 1);

	for (i = 0; i < ne; ++i) {
		printk(KERN_CRIT "Got wc status = %d, content = %d, opcode = %d\n", 
				(int)wc[i].status, (int)wc[i].wr_id, wc[i].opcode);
		if (wc[i].status != IB_WC_SUCCESS) {
			printk(KERN_ALERT "Failed status (%d) for wr_id %d\n",
					wc[i].status, (int) wc[i].wr_id);
			ret = 1;
		}

		switch ((int) wc[i].wr_id) {
			case PINGPONG_SEND_WRID:
				pr_debug("cq got PINGPONG_SEND_WRID\n");
				break;

			case PINGPONG_RECV_WRID:
				pr_debug("cq got PINGPONG_RECV_WRID %s\n", ctx[ctxid]->buf);
				break;

			default:
				printk(KERN_ALERT "Completion for unknown wr_id %d\n",
						(int) wc[i].wr_id);
				ret = 1;
		}
	}
	printk(KERN_CRIT "%s after poll for send\n", __func__); 


	return ret;
}

int routs;
int routine(int ctxid)
{
	struct pingpong_dest     my_dest;
	int                    	 servername = 1;
	int                      ib_port = 1;
	int                      size = MAX_REQ_SIZE;
	enum ib_mtu		 mtu = IB_MTU_2048;
	int                      rx_depth = 1000;
	int                      iters = 0;
	int                      use_event = 0;
	int                      ret;
	int                      rcnt, scnt;	
	int                      sl = 0;
	int			 gidx = -1;
	int			rr;
	char *buf;

	printk(KERN_CRIT "routine %d\n", ctxid);

	page_size = 4096;

	ctx[ctxid] = (struct pingpong_context*)kmalloc(sizeof(struct pingpong_context), GFP_KERNEL);
	if (!ctx[ctxid])
		return NULL;

retry:
	ret = ib_query_port(ib_dev, ib_port, &ctx[ctxid]->portinfo);
        if (ret < 0){
	    printk(KERN_CRIT "ib_query_port failed %d\n", ret);
 	    return 1;
	}
	
   	if (!ctx[ctxid]->portinfo.lid || ctx[ctxid]->portinfo.state != 4) {
		printk(KERN_CRIT "Couldn't get local LID %d state %d\n", ctx[ctxid]->portinfo.lid, ctx[ctxid]->portinfo.state);
		schedule();
		goto retry;
	}
	else
		pr_info("got local LID %d\n", ctx[ctxid]->portinfo.lid);

	ret = pp_init_ctx(ctxid, size, rx_depth, ib_port, use_event);
	if (!ret)
		return 1;

	routs = pp_post_recv(ctxid, ctx[ctxid]->rx_depth);
	if (routs < ctx[ctxid]->rx_depth) {
		printk(KERN_ALERT "Couldn't post receive (%d)\n", routs);
		return 1;
	}

	my_dest.qpn = ctx[ctxid]->qp->qp_num;
	my_dest.psn = 1; //rr & 0xffffff;
	printk(KERN_ALERT "  local address:  QPN 0x%06x\n",
	       my_dest.qpn);

	if (pp_connect_ctx(ctxid, ib_port, my_dest.psn, mtu, sl, 
				gidx))
		return 1;

	ctx[ctxid]->pending = PINGPONG_RECV_WRID;

	struct ib_wc wc[2];
	int ne, i;

	printk(KERN_CRIT "start polling\n");
while (1) {
	do {
		ne = ib_poll_cq(ctx[ctxid]->cq, 2, wc);
		if (ne < 0) {
			pr_debug("poll CQ failed %d\n", ne);
			return 1;
		}
	} while (ne < 1);

	for (i = 0; i < ne; ++i) {
		pr_debug("got cq wr_id %d status %d\n", wc[i].wr_id, wc[i].status);
		if (wc[i].status != IB_WC_SUCCESS) {
			pr_debug("Failed status %d for wr_id %d\n",
					wc[i].status, (int) wc[i].wr_id);
			return 1;
		}

		switch ((int) wc[i].wr_id) {
			case PINGPONG_SEND_WRID:
				++scnt;
				break;

			case PINGPONG_RECV_WRID:
				if (--routs <= 1) {
					routs += pp_post_recv(ctxid, ctx[ctxid]->rx_depth - routs);
					if (routs < ctx[ctxid]->rx_depth) {
						pr_debug("Couldn't post receive (%d)\n",
								routs);
						return 1;
					}
				}
				++rcnt;
				break;

			default:
				pr_debug("Completion for unknown wr_id %d\n",
						(int) wc[i].wr_id);
				return 1;
		}
	}
}

	return 0;

}

static void ibv_add_one(struct ib_device *device)
{
	int i;
	ctx = (struct pingpong_context **)kmalloc(TOTAL_CONNECTIONS*sizeof(struct pingpong_context *), GFP_KERNEL);
	pr_debug("%s ibdev %p pcidef %p dmadev %p\n", __func__, device, device->dev, device->dma_device);
	ib_dev = device;
	routine(0);
}

static void ibv_remove_one(struct ib_device *device)
{
	pp_close_ctx(0);
	return;
}

int lego_ib_init(void)
{
	int ret, i;

	pr_info("%s client mad_got_one %d\n", __func__, mad_got_one);
	while (mad_got_one < 10) {
		schedule();
	}
	pr_info("%s got mad\n", __func__);
	ret = ib_register_client(&ibv_client);
	if (ret) {
		pr_err("couldn't register IB client\n");
		return ret;
	}
	
	return 0;
}

int lego_ib_cleanup(void)
{
	ib_unregister_client(&ibv_client);
	return 0;
}
