//#include <lego/sched.h>
#include <lego/slab.h>
#include <lego/init.h>
#include <lego/mm.h>
//#include <lego/sort.h>
#include <lego/types.h>
//#include <net/sock.h>
//#include <lego/kthread.h>
//#include <lego/workqueue.h>
#include <lego/spinlock.h>
#include <asm/tlbflush.h>
//#include <lego/semaphore.h>
//#include <lego/completion.h>
#include <lego/list.h>
#include <lego/string.h>
//#include <lego/parser.h>
#include <lego/jiffies.h>
#include <lego/atomic.h>
#include <rdma/ib_verbs.h>
//#include <net/sock.h>
//#include <net/tcp.h>
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

#if 0
void wire_gid_to_gid(const char *wgid, union ib_gid *gid)
{
	char tmp[9];
	uint32_t v32;
	int i;

	for (tmp[8] = 0, i = 0; i < 4; ++i) {
		memcpy(tmp, wgid + i * 8, 8);
		sscanf(tmp, "%x", &v32);
		*(uint32_t *)(&gid->raw[i * 4]) = ntohl(v32);
	}
}

void gid_to_wire_gid(const union ib_gid *gid, char wgid[])
{
	int i;

	for (i = 0; i < 4; ++i)
		spr_debug(&wgid[i * 8], "%08x", htonl(*(uint32_t *)(gid->raw + i * 4)));
}
#endif

static void poll_cq(struct ib_cq *cq, void *cq_context)
{
  //struct ibv_device *device = (struct ibv_device *) cq_context;
  struct ib_wc wc;
  int ret;
  while (1) {
//  	ret = ib_peek_cq(cq, 1);
//  	printk(KERN_ALERT "ib_peek_cq %d", ret);
//    TEST_NZ(ib_get_cq_event(s_ctx[ctxid]->comp_channel, cq, cq_context));
    //ib_ack_cq_events(cq, 1);
    ret = ib_req_notify_cq(cq, 0);
	printk(KERN_ALERT "ib_req_notify_cq returned %d\n", ret);
	//if (ret);
//		return NULL;
    //schedule();
    while (ib_poll_cq(cq, 1, &wc)){
     // on_completion(&wc);
      //schedule();
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
			.dlid		= 5, //dest->lid,
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
	attr.timeout	    = 14;
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

#if 0
static struct pingpong_dest *pp_client_exch_dest(int ctxid, const struct pingpong_dest *my_dest)
{
	char kmsg[sizeof "0000:000000:000000:00000000000000000000000000000000"];
	int ret;
	int sockfd = -1;
	struct pingpong_dest *rem_dest = NULL;
	char gid[33];
	struct sockaddr_in addr;
	struct socket		*excsocket;
	

    struct kvec iov = {
            .iov_base = NULL,
            .iov_len = 128,
    };

    struct msghdr msg = {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = (struct iovec *)&iov,
            .msg_iovlen = 1,
            .msg_control = NULL,
            .msg_controllen = 0,
            .msg_flags = 0,
    };

    struct kvec riov = {
            .iov_base = NULL,
            .iov_len = 128,
    };

    struct msghdr rmsg = {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = (struct iovec *)&iov,
            .msg_iovlen = 1,
            .msg_control = NULL,
            .msg_controllen = 0,
            .msg_flags = 0,
    };	

	
	iov.iov_base = kmsg;
	iov.iov_len = sizeof kmsg;
        riov.iov_base = kmsg;
	riov.iov_len = sizeof kmsg;
	
	rem_dest = kmalloc(sizeof (struct pingpong_dest), GFP_KERNEL);
	memset(rem_dest, 0, sizeof (struct pingpong_dest));

	memset(&addr, 0, sizeof (struct sockaddr_in));
        addr.sin_family = AF_INET;
	int port = 17760+ctxid;
	addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl((((((10 << 8) | 1) << 8) | 1) << 8) | 62);
        //addr.sin_addr.s_addr = htonl((((((192 << 8) | 168) << 8) | 123) << 8) | 6);
        printk(KERN_CRIT "ctxid %d connect port %d\n", ctxid, port);

	sockfd = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &excsocket);
	ret = excsocket->ops->connect(excsocket, (struct sockaddr *)&addr, sizeof(addr), 0);

	if (sockfd < 0) {
		printk(KERN_ALERT "Couldn't connect to %d\n", ret);
		return NULL;
	}

	kernel_recvmsg(excsocket, &msg, &iov, 1, iov.iov_len, 0);

	rem_dest = kmalloc(sizeof *rem_dest, GFP_KERNEL);
	if (!rem_dest)
		goto out;
	sscanf(kmsg, "%x:%x:%x:%s", &rem_dest->lid, &rem_dest->qpn,
						&rem_dest->psn, gid);
	printk(KERN_ALERT "LOCAL: [%s]\n", kmsg);
	wire_gid_to_gid(gid, &rem_dest->gid);

	gid_to_wire_gid(&my_dest->gid, gid);
	spr_debug(kmsg, "%04x:%06x:%06x:%s", my_dest->lid, my_dest->qpn,
							my_dest->psn, gid);
	printk(KERN_ALERT "REMOTE: [%s]\n", kmsg);
	kernel_sendmsg(excsocket, &rmsg, &riov, 1, riov.iov_len);


out:
//	close(sockfd);
	return rem_dest;
}
#endif

static int pp_init_ctx(int ctxid, int size, int rx_depth, int port, int use_event)
{
	struct page *pp;

	ctx[ctxid] = (struct pingpong_context*)kmalloc(sizeof(struct pingpong_context), GFP_KERNEL);
	//ctx[ctxid] = kmalloc(sizeof *ctx, GFP_KERNEL);
	if (!ctx[ctxid])
		return NULL;

	ctx[ctxid]->size       = size;
	ctx[ctxid]->send_flags = IB_SEND_SIGNALED;
	ctx[ctxid]->rx_depth   = rx_depth;

        //TODO buf should be page aligned
        pp = alloc_pages(GFP_KERNEL, 2);
        ctx[ctxid]->buf = (char *)page_address(pp);

//      ctx[ctxid]->buf = kmalloc(4096, GFP_KERNEL);
        if (!ctx[ctxid]->buf) {
                printk(KERN_ALERT "Couldn't allocate work buf.\n");
                goto clean_ctx;
        }


        /* FIXME memset(ctx[ctxid]->buf, 0, size); */
        memset(ctx[ctxid]->buf, 0x7b, size);

        ctx[ctxid]->context = ib_dev;
        if (!ctx[ctxid]->context) {
                printk(KERN_ALERT "Couldn't get context for ib_device\n");
                goto clean_buffer;
        }

	ctx[ctxid]->channel = NULL;

	ctx[ctxid]->pd = ctx_pd;
	printk(KERN_CRIT "init ctxid %d pd %p device %p ib_dev %p context %p\n", ctxid, ctx[ctxid]->pd, ctx[ctxid]->pd->device, ib_dev, ctx[ctxid]->context);
	//	ctx[ctxid]->mr = ib_reg_phys_mr(ctx[ctxid]->pd, &bl, 1,  IB_ACCESS_REMOTE_READ | IB_ACCESS_LOCAL_WRITE |IB_ACCESS_REMOTE_WRITE, &bl.addr);
	ctx[ctxid]->mr = ib_get_dma_mr(ctx[ctxid]->pd, IB_ACCESS_LOCAL_WRITE |IB_ACCESS_REMOTE_WRITE| IB_ACCESS_REMOTE_READ);
	if (!ctx[ctxid]->mr) {
		printk(KERN_ALERT "Couldn't register MR\n");
		goto clean_pd;
	}
	else
		pr_debug("got mr %p\n", ctx[ctxid]->mr);

        ctx[ctxid]->uaddr = ib_dma_map_single(ib_dev, ctx[ctxid]->buf, 4096, DMA_BIDIRECTIONAL);

        printk(KERN_ALERT "mr.lkey: %x\n", ctx[ctxid]->mr->lkey);


	ctx[ctxid]->cq = ib_create_cq(ctx[ctxid]->context, poll_cq, NULL, NULL, rx_depth+1, 0);
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

//	kfree(ctx[ctxid]->buf);
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
//	struct ib_sge list = {
//		.addr	= uaddr,//(uintptr_t) ctx[ctxid]->buf,
//		.length = size,
//		.lkey	= ctx[ctxid]->mr->lkey
//	};
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
//, unsigned long reqid)
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
		//	spin_unlock(&send_req_lock[ctxid]);
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
//int routine(int ctxid, struct ib_device *ib_dev_input)
int routine(int ctxid)
//int routine(void *input)
{
	struct pingpong_dest     my_dest;
//	struct pingpong_dest    *rem_dest;	
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
//	ib_dev = ib_dev_input;

	page_size = 4096;

	ret = pp_init_ctx(ctxid, size, rx_depth, ib_port, use_event);
	if (!ret)
		return 1;

	routs = pp_post_recv(ctxid, ctx[ctxid]->rx_depth);
	if (routs < ctx[ctxid]->rx_depth) {
		printk(KERN_ALERT "Couldn't post receive (%d)\n", routs);
		return 1;
	}

#if 0
	if (use_event)
	if (ib_req_notify_cq(ctx[ctxid]->cq, 0)) {
			printk(KERN_ALERT "Couldn't request CQ notification\n");
			return 1;
	}
#endif

	ret = ib_query_port(ib_dev, 1, &ctx[ctxid]->portinfo);
        if (ret < 0){
	    printk(KERN_CRIT "ib_query_port failed %d\n", ret);
 	    return 1;
	}
	
//	my_dest.lid = ctx[ctxid]->portinfo.lid;
  // 	if (!my_dest.lid) {
//		printk(KERN_CRIT "Couldn't get local LID\n");
//		return 1;
//	}

	my_dest.qpn = ctx[ctxid]->qp->qp_num;
	//get_random_bytes(&rr, sizeof(int));
	my_dest.psn = 1; //rr & 0xffffff;
	//inet_ntop(AF_INET6, &my_dest.gid, gid, sizeof gid);
	//printk(KERN_ALERT "  local address:  LID 0x%04x, QPN 0x%06x\n",
	  //     my_dest.lid, my_dest.qpn);
	printk(KERN_ALERT "  local address:  QPN 0x%06x\n",
	       my_dest.qpn);


	/* actually client */
//	rem_dest = pp_client_exch_dest(ctxid, &my_dest);

//	if (!rem_dest)
//		return 1;

//	printk(KERN_ALERT "  remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x, PORT %d\n",
//					       rem_dest->lid, rem_dest->qpn, rem_dest->psn, ib_port);

//	if (servername)
		if (pp_connect_ctx(ctxid, ib_port, my_dest.psn, mtu, sl, 
					gidx))
//			return 1;

//	send_msg(0, NULL, 4);

	ctx[ctxid]->pending = PINGPONG_RECV_WRID;

	struct ib_wc wc[2];
	int ne, i;

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
	return 0;

}

static void ibv_add_one(struct ib_device *device)
{
	int i;
	ctx = (struct pingpong_context **)kmalloc(TOTAL_CONNECTIONS*sizeof(struct pingpong_context *), GFP_KERNEL);
	pr_debug("%s ibdev %p pcidef %p dmadev %p\n", __func__, device, device->dev, device->dma_device);
	ib_dev = device;
		ctx_pd = ib_alloc_pd(device);
		if (!ctx_pd) {
			printk(KERN_ALERT "Couldn't allocate PD\n");
		}
	routine(0);
//	for (i = 0; i < TOTAL_CONNECTIONS; i++)
//		kthread_run(routine, (void*)i, "ib routine");
}

static void ibv_remove_one(struct ib_device *device)
{
	pp_close_ctx(0);
	return;
}

int lego_ib_init(void)
{
	int ret, i;

	ret = ib_register_client(&ibv_client);
	if (ret) {
		pr_err("couldn't register IB client\n");
		return ret;
	}
	
	return 0;
}

void lego_ib_cleanup(void)
{
	ib_unregister_client(&ibv_client);
}
