#include <linux/sched.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/sba.h>
#include <linux/socket.h>
#include <linux/sort.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/memory.h>
#include <linux/pagemap.h>
#include <linux/mm_inline.h>
#include <linux/rmap.h>
#include <linux/buffer_head.h>
#include <asm/tlbflush.h>
#include <linux/semaphore.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/parser.h>
#include <linux/random.h>
#include <linux/jiffies.h>
#include <linux/device.h>
#include <linux/atomic.h>
#include <rdma/ib_verbs.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/types.h>
#include <linux/syscalls.h>

MODULE_AUTHOR("jiy092");
MODULE_LICENSE("Dual BSD/GPL");

atomic_t global_reqid;
//#define DEBUG_IBV

struct ib_device *ib_dev;
struct ib_pd *ctx_pd;
struct ib_pd *ctx_pd_1;

spinlock_t send_req_lock[TOTAL_CONNECTIONS];

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
	void			*buf;
	char			**buf1;
	unsigned long		*uaddr1;
	unsigned long		*uaddr2;
	unsigned long		*uaddr3;
	unsigned long		*uaddr4;
	int			 size;
	int			 send_flags;
	int			 rx_depth;
	int			 pending;
	struct ib_port_attr     portinfo;
	u64			uaddr;
};
struct pingpong_context **ctx;

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

static struct class ibv_class = {
	.name    = "infiniband_ibvs",
	.dev_release = ibv_release_dev
};

struct pingpong_context_1 {
	struct ib_device	*context;
	struct ib_comp_channel *channel;
	struct ib_pd		*pd;
	struct ib_mr		*mr;
	struct ib_cq		*cq;
	struct ib_qp		*qp;
	void			*buf;
	int			 size;
	int			 send_flags;
	int			 rx_depth;
	int			 pending;
	struct ib_port_attr     portinfo;
	u64			uaddr;
};

struct pingpong_context_1 **ctx1;

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
                sprintf(&wgid[i * 8], "%08x", htonl(*(uint32_t *)(gid->raw + i * 4)));
}


static void poll_cq(struct ib_cq *cq, void *cq_context)
{
  //struct ibv_device *device = (struct ibv_device *) cq_context;
  struct ib_wc wc;
  int ret;
  while (1) {
//  	ret = ib_peek_cq(cq, 1);
    printk(KERN_ALERT "get cq \n");
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

static int pp_connect_ctx_1(int ctxid, int port, int my_psn,
			  enum ib_mtu mtu, int sl,
			  struct pingpong_dest *dest, int sgid_idx)
{
	struct ib_qp_attr attr = {
		.qp_state		= IB_QPS_RTR,
		.path_mtu		= mtu,
		.dest_qp_num		= dest->qpn,
		.rq_psn			= dest->psn,
		.max_dest_rd_atomic	= 1,
		.min_rnr_timer		= 12,
		.ah_attr		= {
			.dlid		= dest->lid,
			.sl		= sl,
			.src_path_bits	= 0,
			.port_num	= port
		}
	};


	if (ib_modify_qp(ctx1[ctxid]->qp, &attr,
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
	if (ib_modify_qp(ctx1[ctxid]->qp, &attr,
			  IB_QP_STATE              |
			  IB_QP_TIMEOUT            |
			  IB_QP_RETRY_CNT          |
			  IB_QP_RNR_RETRY          |
			  IB_QP_SQ_PSN             |
			  IB_QP_MAX_QP_RD_ATOMIC)) {
		printk(KERN_ALERT "Failed to modify QP to RTS\n");
		return 1;
	}

	return 0;
}

static struct pingpong_dest *pp_client_exch_dest_1(int ctxid, const struct pingpong_dest *my_dest)
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
	int port = 17780+ctxid;
	addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl((((((10 << 8) | 1) << 8) | 1) << 8) | 73);

	sockfd = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &excsocket);
	ret = excsocket->ops->connect(excsocket, (struct sockaddr *)&addr, sizeof(addr), 0);
	printk(KERN_CRIT "exch 1 after connect\n");

	if (sockfd < 0) {
		printk(KERN_ALERT "Couldn't connect to %d\n", ret);
		return NULL;
	}

	kernel_recvmsg(excsocket, &msg, &iov, 1, iov.iov_len, 0);
	printk(KERN_CRIT "exch 1 after recvmsg\n");

	rem_dest = kmalloc(sizeof *rem_dest, GFP_KERNEL);
	if (!rem_dest)
		goto out;
	sscanf(kmsg, "%x:%x:%x:%s", &rem_dest->lid, &rem_dest->qpn,
						&rem_dest->psn, gid);
	printk(KERN_ALERT "LOCAL: [%s]\n", kmsg);
	wire_gid_to_gid(gid, &rem_dest->gid);

	gid_to_wire_gid(&my_dest->gid, gid);
	sprintf(kmsg, "%04x:%06x:%06x:%s", my_dest->lid, my_dest->qpn,
							my_dest->psn, gid);
	printk(KERN_ALERT "REMOTE: [%s]\n", kmsg);
	kernel_sendmsg(excsocket, &rmsg, &riov, 1, riov.iov_len);


out:
//	close(sockfd);
	return rem_dest;
}


static int pp_init_ctx_1(int ctxid, int size, int rx_depth, int port, int use_event)
{
	struct page *pp;

	ctx1[ctxid] = (struct pingpong_context_1*)kmalloc(sizeof(struct pingpong_context_1), GFP_KERNEL);
	//ctx1[ctxid] = kmalloc(sizeof *ctx, GFP_KERNEL);
	if (!ctx1[ctxid])
		return NULL;

	ctx1[ctxid]->size       = size;
	ctx1[ctxid]->send_flags = IB_SEND_SIGNALED;
	ctx1[ctxid]->rx_depth   = rx_depth;

        //TODO buf should be page aligned
        pp = alloc_pages(GFP_KERNEL, 2);
        ctx1[ctxid]->buf = page_address(pp);

//      ctx1[ctxid]->buf = kmalloc(4096, GFP_KERNEL);
        if (!ctx1[ctxid]->buf) {
                printk(KERN_ALERT "Couldn't allocate work buf.\n");
                goto clean_ctx;
        }


        /* FIXME memset(ctx1[ctxid]->buf, 0, size); */
        memset(ctx1[ctxid]->buf, 0x7b, size);

        ctx1[ctxid]->context = ib_dev;
        if (!ctx1[ctxid]->context) {
                printk(KERN_ALERT "Couldn't get context for ib_device\n");
                goto clean_buffer;
        }

/*
	if (use_event) {
		ctx1[ctxid]->channel = ib_create_comp_channel(ctx1[ctxid]->context);
		if (!ctx1[ctxid]->channel) {
			printk(KERN_ALERT "Couldn't create completion channel\n");
			goto clean_device;
		}
	} else */
	ctx1[ctxid]->channel = NULL;

	ctx1[ctxid]->pd = ctx_pd_1;
	printk(KERN_CRIT "init ctxid %d pd %p device %p ib_dev %p context %p\n", ctxid, ctx1[ctxid]->pd, ctx1[ctxid]->pd->device, ib_dev, ctx1[ctxid]->context);
	//	ctx1[ctxid]->mr = ib_reg_phys_mr(ctx1[ctxid]->pd, &bl, 1,  IB_ACCESS_REMOTE_READ | IB_ACCESS_LOCAL_WRITE |IB_ACCESS_REMOTE_WRITE, &bl.addr);
	ctx1[ctxid]->mr = ib_get_dma_mr(ctx1[ctxid]->pd, IB_ACCESS_LOCAL_WRITE |IB_ACCESS_REMOTE_WRITE| IB_ACCESS_REMOTE_READ);
	if (!ctx1[ctxid]->mr) {
		printk(KERN_ALERT "Couldn't register MR\n");
		goto clean_pd;
	}

        ctx1[ctxid]->uaddr = ib_dma_map_single(ib_dev, ctx1[ctxid]->buf, 4096, DMA_BIDIRECTIONAL);

        printk(KERN_ALERT "mr.lkey: %x\n", ctx1[ctxid]->mr->lkey);


	ctx1[ctxid]->cq = ib_create_cq(ctx1[ctxid]->context, poll_cq, NULL, NULL, rx_depth+1, 0);
	if (!ctx1[ctxid]->cq) {
		printk(KERN_ALERT "Couldn't create CQ\n");
		goto clean_mr;
	}

	{
		struct ib_qp_attr attr;
		struct ib_qp_init_attr init_attr = {
			.send_cq = ctx1[ctxid]->cq,
			.recv_cq = ctx1[ctxid]->cq,
			.cap     = {
				.max_send_wr  = 1,
				.max_recv_wr  = rx_depth,
				.max_send_sge = 10,
				.max_recv_sge = 1
			},
			.qp_type = IB_QPT_RC
		};

		ctx1[ctxid]->qp = ib_create_qp(ctx1[ctxid]->pd, &init_attr);
		if (!ctx1[ctxid]->qp)  {
			printk(KERN_ALERT "Couldn't create QP\n");
			goto clean_cq;
		}

		ib_query_qp(ctx1[ctxid]->qp, &attr, IB_QP_CAP, &init_attr);
		if (init_attr.cap.max_inline_data >= size) {
			ctx1[ctxid]->send_flags |= IB_SEND_INLINE;
		}
	}

	{
		struct ib_qp_attr attr = {
			.qp_state        = IB_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = port,
			.qp_access_flags = 0
		};

		if (ib_modify_qp(ctx1[ctxid]->qp, &attr,
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
	ib_destroy_qp(ctx1[ctxid]->qp);

clean_cq:
	ib_destroy_cq(ctx1[ctxid]->cq);

clean_mr:
	ib_dereg_mr(ctx1[ctxid]->mr);

clean_pd:
	ib_dealloc_pd(ctx1[ctxid]->pd);

clean_buffer:
	kfree(ctx1[ctxid]->buf);

clean_ctx:
	kfree(ctx);

	return NULL;
}

int pp_close_ctx_1(int ctxid)
{
	if (ib_destroy_qp(ctx1[ctxid]->qp)) {
		printk(KERN_ALERT "Couldn't destroy QP\n");
		return 1;
	}

	if (ib_destroy_cq(ctx1[ctxid]->cq)) {
		printk(KERN_ALERT "Couldn't destroy CQ\n");
		return 1;
	}

	if (ib_dereg_mr(ctx1[ctxid]->mr)) {
		printk(KERN_ALERT "Couldn't deregister MR\n");
		return 1;
	}

	if (ib_dealloc_pd(ctx1[ctxid]->pd)) {
		printk(KERN_ALERT "Couldn't deallocate PD\n");
		return 1;
	}

//	kfree(ctx1[ctxid]->buf);
	kfree(ctx);

	return 0;
}

static int pp_post_recv_1(int ctxid, int n)
{
	struct ib_sge list = {
		.addr	= ctx1[ctxid]->uaddr, //(uintptr_t) ctx1[ctxid]->buf,
		.length = ctx1[ctxid]->size,
		.lkey	= ctx1[ctxid]->mr->lkey
	};
	struct ib_recv_wr wr = {
		.wr_id	    = PINGPONG_RECV_WRID,
		.sg_list    = &list,
		.num_sge    = 1,
	};
	struct ib_recv_wr *bad_wr;
	int i;

	for (i = 0; i < n; ++i)
		if (ib_post_recv(ctx1[ctxid]->qp, &wr, &bad_wr))
			break;

	return i;
}

static int pp_post_recv1_1(int ctxid)
{
	struct ib_sge list = {
		.addr	= ctx1[ctxid]->uaddr, //(uintptr_t) ctx1[ctxid]->buf,
		.length = ctx1[ctxid]->size,
		.lkey	= ctx1[ctxid]->mr->lkey
	};
	struct ib_recv_wr wr = {
		.wr_id	    = PINGPONG_RECV_WRID,
		.sg_list    = &list,
		.num_sge    = 1,
	};
	struct ib_recv_wr *bad_wr;
	int i, ret;

	ret = ib_post_recv(ctx1[ctxid]->qp, &wr, &bad_wr);

	return ret;
}

static int pp_post_send_1(int ctxid)
{
	struct ib_sge list = {
		.addr	= ctx1[ctxid]->uaddr,//(uintptr_t) ctx1[ctxid]->buf,
		.length = ctx1[ctxid]->size,
		.lkey	= ctx1[ctxid]->mr->lkey
	};
	struct ib_send_wr wr = {
		.wr_id	    = PINGPONG_SEND_WRID,
		.sg_list    = &list,
		.num_sge    = 1,
		.opcode     = IB_WR_SEND,
		.send_flags = ctx1[ctxid]->send_flags,
	};
	struct ib_send_wr *bad_wr;

	return ib_post_send(ctx1[ctxid]->qp, &wr, &bad_wr);
}

static int pp_post_send1_1(int ctxid, struct ib_sge *list, int num_sge)
{
//	struct ib_sge list = {
//		.addr	= uaddr,//(uintptr_t) ctx1[ctxid]->buf,
//		.length = size,
//		.lkey	= ctx1[ctxid]->mr->lkey
//	};
	struct ib_send_wr wr = {
		.wr_id	    = PINGPONG_SEND_WRID,
		.sg_list    = list,
		.num_sge    = num_sge,
		.opcode     = IB_WR_SEND,
		.send_flags = ctx1[ctxid]->send_flags,
	};
	struct ib_send_wr *bad_wr;

	return ib_post_send(ctx1[ctxid]->qp, &wr, &bad_wr);
}

int routs_1;
//int routine_1(int ctxid, struct ib_device *ib_dev_input)
int routine_1(void *input)
{
	struct pingpong_dest     my_dest;
	struct pingpong_dest    *rem_dest;	
	int                    	 servername = 1;
	int                      ib_port = 1;
	int                      size = 4096*2;
	enum ib_mtu		 mtu = IB_MTU_2048;
	int                      rx_depth = 11000;
	int                      iters = 0;
	int                      use_event = 0;
	int                      ret;
	int                      rcnt, scnt;	
	int                      sl = 0;
	int			 gidx = -1;
	int			rr;
	struct timeval		ts_start, ts_end;
	char *buf;

	int ctxid = (int)input;
	printk(KERN_CRIT "routine %d\n", ctxid);
//	ib_dev = ib_dev_input;
        int x = rdma_port_get_link_layer(ib_dev, 1);
	printk(KERN_ALERT "IB_CLIENT %p LINKLAYER %x\n", ib_dev, x);

	page_size = 4096;

	ret = pp_init_ctx_1(ctxid, size, rx_depth, ib_port, use_event);
	if (!ret)
		return 1;

	routs_1 = pp_post_recv_1(ctxid, ctx1[ctxid]->rx_depth);
	if (routs_1 < ctx1[ctxid]->rx_depth) {
		printk(KERN_ALERT "Couldn't post receive (%d)\n", routs_1);
		return 1;
	}

	if (use_event)
	if (ib_req_notify_cq(ctx1[ctxid]->cq, 0)) {
			printk(KERN_ALERT "Couldn't request CQ notification\n");
			return 1;
	}

	ret = ib_query_port(ib_dev, 1, &ctx1[ctxid]->portinfo);
        if (ret < 0){
	    printk(KERN_CRIT "ib_query_port failed %d\n", ret);
 	    return 1;
	}
	
	my_dest.lid = ctx1[ctxid]->portinfo.lid;
   	if (!my_dest.lid) {
		printk(KERN_CRIT "Couldn't get local LID\n");
		return 1;
	}

	if (gidx >= 0) {
		if (ib_query_gid(ctx1[ctxid]->context, ib_port, gidx, &my_dest.gid)) {
			printk(KERN_ALERT "can't read sgid of index %d\n", gidx);
			return 1;
		}
	} else
		memset(&my_dest.gid, 0, sizeof my_dest.gid);


	my_dest.qpn = ctx1[ctxid]->qp->qp_num;
	get_random_bytes(&rr, sizeof(int));
	my_dest.psn = rr & 0xffffff;
	//inet_ntop(AF_INET6, &my_dest.gid, gid, sizeof gid);
	printk(KERN_ALERT "  local address:  LID 0x%04x, QPN 0x%06x, PSN 0x%06x\n",
	       my_dest.lid, my_dest.qpn, my_dest.psn);


	/* actually client */
	rem_dest = pp_client_exch_dest_1(ctxid, &my_dest);

	if (!rem_dest)
		return 1;

	printk(KERN_ALERT "  remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x, PORT %d\n",
					       rem_dest->lid, rem_dest->qpn, rem_dest->psn, ib_port);

	if (servername)
		if (pp_connect_ctx_1(ctxid, ib_port, my_dest.psn, mtu, sl, rem_dest,
					gidx))
			return 1;
	return 0;

}

int network_worker_func_sync_ibverbs(int ctxid, int if_last, unsigned long phys_addr, unsigned long hva, int len)
{
	unsigned long reqid;
	int ret = 0;
	int i;
	struct ib_sge sge_list[4];
	u64 uaddr;
	int size;

	size = sizeof(unsigned long);
        uaddr = ib_dma_map_single(ib_dev, (void*)&phys_addr, size, DMA_BIDIRECTIONAL);
	if (ret = ib_dma_mapping_error(ib_dev, uaddr)) {
		printk(KERN_CRIT "dma_map_single error %d uaddr %llx\n", ret, uaddr);
	}
	sge_list[0].addr = uaddr;
	sge_list[0].length = size;
	sge_list[0].lkey = ctx1[ctxid]->mr->lkey; 

	int ori_len = len;
	size = sizeof(int);
	if (len > MAX_REQ_SIZE) {
		printk(KERN_CRIT "error: too big unit req size %d phys_addr %llx hva %llx\n", len, phys_addr, hva);
		len = 4096;
	}
	if (if_last == 1)
		len = 0x4000 + len;
	if (len <= 0) {
		printk(KERN_CRIT "error: ctxid %d iflast %d ori_len %d len %d key %llx reqid %llu\n", 
				ctxid, reqid, ori_len, len, phys_addr, reqid);
		len = ori_len;
	}
        uaddr = ib_dma_map_single(ib_dev, (void*)&len, size, DMA_BIDIRECTIONAL);
	if (ret = ib_dma_mapping_error(ib_dev, uaddr)) {
		printk(KERN_CRIT "dma_map_single error %d uaddr %llx\n", ret, uaddr);
	}
	sge_list[1].addr = uaddr;
	sge_list[1].length = size;
	sge_list[1].lkey = ctx1[ctxid]->mr->lkey; 

	size = ori_len;
	//unsigned long rounded_data = (unsigned long)hva - (unsigned long)hva % PAGE_SIZE;
	//unsigned long offset_data = hva - rounded_data;
	//unsigned long pfn = vmalloc_to_pfn(rounded_data);
	//struct page *page = pfn_to_page(pfn);
	//uaddr = ib_dma_map_page(ib_dev, page, offset_data, ori_len, DMA_BIDIRECTIONAL);
	uaddr = ib_dma_map_single(ib_dev, (void*)hva, size, DMA_BIDIRECTIONAL);
	if (ret = ib_dma_mapping_error(ib_dev, uaddr)) {
		printk(KERN_CRIT "dma_map_single error %d uaddr %llx\n", ret, uaddr);
	}
//	else
//		printk(KERN_CRIT "map data uaddr %llx len %d hav %llx pfn %llx offset %d\n", uaddr, len, hva, pfn, offset_data);
	sge_list[3].addr = uaddr;
	sge_list[3].length = size;
	sge_list[3].lkey = ctx1[ctxid]->mr->lkey; 

resend_req:
#ifdef DEBUG_IBV
	printk(KERN_CRIT "before lock pid %d: network_worker_func_sync_ibverbs ctxid %d iflast %d reqid %llu phys_addr %llx len %d content %llx\n", 
			current->pid, ctxid, if_last, reqid, phys_addr, len, hva);
#endif
	spin_lock(&send_req_lock[ctxid]);

	reqid = atomic_add_return(1, &global_reqid); //(unsigned long)riov[i].virt_addr;
	size = sizeof(unsigned long);
        uaddr = ib_dma_map_single(ib_dev, (void*)&reqid, size, DMA_BIDIRECTIONAL);
	if (ret = ib_dma_mapping_error(ib_dev, uaddr)) {
		printk(KERN_CRIT "dma_map_single error %d uaddr %llx\n", ret, uaddr);
	}
	sge_list[2].addr = uaddr;
	sge_list[2].length = size;
	sge_list[2].lkey = ctx1[ctxid]->mr->lkey; 

	ret = pp_post_send1_1(ctxid, sge_list, 4);

	ctx1[ctxid]->pending |= PINGPONG_SEND_WRID;
	struct ib_wc wc[2];
	int ne;
	do {
		ne = ib_poll_cq(ctx1[ctxid]->cq, 1, wc);
		if (ne < 0) {
			printk(KERN_ALERT "poll CQ failed %d\n", ne);
			spin_unlock(&send_req_lock[ctxid]);
			return 1;
		}

	} while (ne < 1);
	for (i = 0; i < ne; ++i) {
//					printk(KERN_CRIT "pid %d: Got wc status = %d, content = %d, opcode = %d\n", 
//							current->pid, (int)wc[i].status, (int)wc[i].wr_id, wc[i].opcode);
		if (wc[i].status != IB_WC_SUCCESS) {
			printk(KERN_ALERT "error: network_worker_func_sync_ibverbs pid %d Failed status (%d) for wr_id %d\n",
					current->pid, wc[i].status, (int) wc[i].wr_id);
	printk(KERN_CRIT "pid %d: network_worker_func_sync_ibverbs reqid %llu phys_addr %llx len %d content %llx\n", 
			current->pid, reqid, phys_addr, len, hva);
			ret = 1;
		}

		switch ((int) wc[i].wr_id) {
			case PINGPONG_SEND_WRID:
				break;

			case PINGPONG_RECV_WRID:
				break;

			default:
				printk(KERN_ALERT "Completion for unknown wr_id %d\n",
						(int) wc[i].wr_id);
				ret = 1;
		}
	}
	spin_unlock(&send_req_lock[ctxid]);
#ifdef DEBUG_IBV
	printk(KERN_CRIT "after lock pid %d: network_worker_func_sync_ibverbs ctxid %d reqid %llu phys_addr %llx len %d content %llx\n", 
			current->pid, ctxid, reqid, phys_addr, len, hva);
#endif

	if (ret != 0) {
		printk(KERN_CRIT "pid %d replicate_pages failed at send ret %d\n", current->pid, ret);
	//	goto resend_req;
	}
	else {
	}
	return ret;
}
EXPORT_SYMBOL(network_worker_func_sync_ibverbs);


static int pp_connect_ctx(int ctxid, int port, int my_psn,
			  enum ib_mtu mtu, int sl,
			  struct pingpong_dest *dest, int sgid_idx)
{
	int ret;

	struct ib_qp_attr attr = {
		.qp_state		= IB_QPS_RTR,
		.path_mtu		= mtu,
		.dest_qp_num		= dest->qpn,
		.rq_psn			= dest->psn,
		.max_dest_rd_atomic	= 1,
		.min_rnr_timer		= 12,
		.ah_attr		= {
			.dlid		= dest->lid,
			.sl		= sl,
			.src_path_bits	= 0,
			.port_num	= port
		}
	};

	printk(KERN_ALERT "MTU %d QPN %d PSN  %d LID%d SL%d port %d\n", mtu, dest->qpn, dest->psn, dest->lid, sl, port);
	ret = ib_modify_qp(ctx[ctxid]->qp, &attr,
			  IB_QP_STATE              |
			  IB_QP_AV                 |
			  IB_QP_PATH_MTU           |
			  IB_QP_DEST_QPN           |
			  IB_QP_RQ_PSN             |
			  IB_QP_MAX_DEST_RD_ATOMIC |
			  IB_QP_MIN_RNR_TIMER);
	if (ret) {
		printk(KERN_ALERT "Failed to modify QP to RTR %d\n", ret);
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

	return 0;
}


static struct pingpong_dest *pp_server_exch_dest(int ctxid, int ib_port, enum ib_mtu mtu,
						 int sl,
						 const struct pingpong_dest *my_dest,
						 int sgid_idx)
{
	char kmsg[sizeof "0000:000000:000000:00000000000000000000000000000000"];
	int ret;
	int sockfd = -1;
	struct pingpong_dest *rem_dest = NULL;
	char gid[33];
	struct sockaddr_in addr;
	struct socket	*excsocket, *newsock;
	

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
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

	sockfd = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &excsocket);
	ret = excsocket->ops->bind(excsocket, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0){
            printk(KERN_CRIT "socket bind failed %d\n", ret);
            return NULL;
    }
    ret = excsocket->ops->listen(excsocket, 5);
    if (ret < 0){
        printk(KERN_CRIT "socket listen failed\n");
        return NULL;
    }

    ret = sock_create(PF_INET, SOCK_STREAM, 6, &newsock);
    if (ret < 0){
        printk(KERN_CRIT "newsocket create failed\n");
        return NULL;
    }
    newsock->ops = excsocket->ops;

    ret = excsocket->ops->accept(excsocket, newsock, 0);
    if (ret < 0){
        printk(KERN_CRIT "newsocket accept failed %d\n", ret);
        return NULL;
    }	
	
	
	gid_to_wire_gid(&my_dest->gid, gid);
	sprintf(kmsg, "%04x:%06x:%06x:%s", my_dest->lid, my_dest->qpn,
							my_dest->psn, gid);
	printk(KERN_ALERT "LOCAL: [%s]\n", kmsg);
	kernel_sendmsg(newsock, &rmsg, &riov, 1, riov.iov_len);
	memset(kmsg, 0, sizeof kmsg);
	kernel_recvmsg(newsock, &msg, &iov, 1, iov.iov_len, 0);



	rem_dest = kmalloc(sizeof *rem_dest, GFP_KERNEL);
	if (!rem_dest)
		goto out;
	sscanf(kmsg, "%x:%x:%x:%s", &rem_dest->lid, &rem_dest->qpn,
						&rem_dest->psn, gid);
	printk(KERN_ALERT "REMOTE: [%s]\n", kmsg);
	wire_gid_to_gid(gid, &rem_dest->gid);
	if (pp_connect_ctx(ctxid, ib_port, my_dest->psn, mtu, sl, rem_dest, sgid_idx)) {
		printk(KERN_ALERT "Couldn't connect to remote QP\n");
		kfree(rem_dest);
		rem_dest = NULL;
		goto out;
	}


out:
//	close(sockfd);
	return rem_dest;
}

int ibv_event_handler(struct ib_cq *cq, void *context)
{

	struct ib_wc wc[1];
	int ne, i, ret = 0;

}

static int pp_init_ctx(int ctxid, int size, int rx_depth, int port, int use_event)
{
	struct page *pp;

	ctx[ctxid] = (struct pingpong_context*)kmalloc(sizeof(struct pingpong_context), GFP_KERNEL);
	if (!ctx[ctxid])
		return NULL;

	ctx[ctxid]->size       = size;
	ctx[ctxid]->send_flags = IB_SEND_SIGNALED;
	ctx[ctxid]->rx_depth   = rx_depth;

	pp = alloc_pages(GFP_KERNEL, 2);
	ctx[ctxid]->buf = page_address(pp);

	if (!ctx[ctxid]->buf) {
		printk(KERN_ALERT "Couldn't allocate work buf.\n");
		goto clean_ctx;
	}


	/* FIXME memset(ctx[ctxid]->buf, 0, size); */
	memset(ctx[ctxid]->buf, 0, size);

	ctx[ctxid]->context = ib_dev;
	if (!ctx[ctxid]->context) {
		printk(KERN_ALERT "Couldn't get context for ib_device\n");
		goto clean_buffer;
	}
/*
	if (use_event) {
		ctx[ctxid]->channel = ib_create_comp_channel(ctx[ctxid]->context);
		if (!ctx[ctxid]->channel) {
			printk(KERN_ALERT "Couldn't create completion channel\n");
			goto clean_device;
		}
	} elsei*/
		ctx[ctxid]->channel = NULL;

	//ctx[ctxid]->pd = ctx1[0]->pd;
	ctx[ctxid]->pd = ctx_pd;
	ctx[ctxid]->mr = ib_get_dma_mr(ctx[ctxid]->pd, IB_ACCESS_REMOTE_READ | IB_ACCESS_LOCAL_WRITE |IB_ACCESS_REMOTE_WRITE);
	if (!ctx[ctxid]->mr) {
		printk(KERN_ALERT "Couldn't register MR\n");
		goto clean_pd;
	}

	ctx[ctxid]->uaddr = ib_dma_map_single(ib_dev, ctx[ctxid]->buf, 4096, DMA_BIDIRECTIONAL);

#if 0
	ctx[ctxid]->buf1 = kmalloc(2*sizeof(unsigned long)+sizeof(int)+PAGE_SIZE, GFP_KERNEL);
	BUG_ON(!ctx[ctxid]->buf1);
	ctx[ctxid]->uaddr1 = ib_dma_map_single(ib_dev, ctx[ctxid]->buf1, sizeof(unsigned long), DMA_BIDIRECTIONAL);
	ctx[ctxid]->uaddr2 = ib_dma_map_single(ib_dev, ctx[ctxid]->buf1+sizeof(unsigned long), sizeof(unsigned long), DMA_BIDIRECTIONAL);
	ctx[ctxid]->uaddr3 = ib_dma_map_single(ib_dev, ctx[ctxid]->buf1+2*sizeof(unsigned long), sizeof(int), DMA_BIDIRECTIONAL);
	ctx[ctxid]->uaddr4 = ib_dma_map_single(ib_dev, ctx[ctxid]->buf1+2*sizeof(unsigned long)+sizeof(int), PAGE_SIZE, DMA_BIDIRECTIONAL);
#else
	ctx[ctxid]->buf1 = (char **)kmalloc(TOTAL_JOURNAL_SIZE*sizeof(char*), GFP_KERNEL);
	ctx[ctxid]->uaddr1 = (char **)kmalloc(TOTAL_JOURNAL_SIZE*sizeof(unsigned long), GFP_KERNEL);
	ctx[ctxid]->uaddr2 = (char **)kmalloc(TOTAL_JOURNAL_SIZE*sizeof(unsigned long), GFP_KERNEL);
	ctx[ctxid]->uaddr3 = (char **)kmalloc(TOTAL_JOURNAL_SIZE*sizeof(unsigned long), GFP_KERNEL);
	ctx[ctxid]->uaddr4 = (char **)kmalloc(TOTAL_JOURNAL_SIZE*sizeof(unsigned long), GFP_KERNEL);
	BUG_ON(!ctx[ctxid]->buf1||!ctx[ctxid]->uaddr1||!ctx[ctxid]->uaddr2||!ctx[ctxid]->uaddr3);
	int i;
	unsigned long phys_addr, prev_phys_addr = 0, prev_virt_addr = 0;
	for (i = 0; i < TOTAL_JOURNAL_SIZE; i++) {
		ctx[ctxid]->buf1[i] = (void *)kmalloc(MAX_REQ_SIZE + 4*sizeof(unsigned long) + sizeof(int), GFP_ATOMIC);	
		BUG_ON(!ctx[ctxid]->buf1[i]);
		memset(ctx[ctxid]->buf1[i], 0, 4*sizeof(unsigned long)+sizeof(int)+MAX_REQ_SIZE);
		phys_addr = __pa(ctx[ctxid]->buf1[i]);
		if (i < 10)
			printk(KERN_CRIT "init buf %d phys_addr %llx virt_addr %p\n", i, phys_addr, ctx[ctxid]->buf1[i]);
		// 1st ul key (offset of the pmfs partition)
		// 2nd ul phys address of the mapping
		memcpy(ctx[ctxid]->buf1[i]+sizeof(unsigned long), &phys_addr, sizeof(unsigned long));
		// 3rd int size
		// 4th reqid
		//4th ul the phys address of previous mapping
//		memcpy(ctx[ctxid]->buf1[i]+2*sizeof(unsigned long)+sizeof(int), &prev_phys_addr, sizeof(unsigned long));
		// 5th ul the phys address of next mapping, first set to 0
//		if (prev_phys_addr > 0)
//			memcpy(prev_virt_addr, &phys_addr, sizeof(unsigned long));
		prev_phys_addr = phys_addr;
		prev_virt_addr = ctx[ctxid]->buf1[i]+3*sizeof(unsigned long)+sizeof(int);
		ctx[ctxid]->uaddr1[i] = ib_dma_map_single(ib_dev, ctx[ctxid]->buf1[i], sizeof(unsigned long), DMA_BIDIRECTIONAL);
		ctx[ctxid]->uaddr2[i] = ib_dma_map_single(ib_dev, ctx[ctxid]->buf1[i]+2*sizeof(unsigned long), sizeof(int), DMA_BIDIRECTIONAL);
		ctx[ctxid]->uaddr4[i] = ib_dma_map_single(ib_dev, ctx[ctxid]->buf1[i]+2*sizeof(unsigned long)+sizeof(int), sizeof(unsigned long), DMA_BIDIRECTIONAL);
		ctx[ctxid]->uaddr3[i] = ib_dma_map_single(ib_dev, ctx[ctxid]->buf1[i]+4*sizeof(unsigned long)+sizeof(int), MAX_REQ_SIZE, DMA_BIDIRECTIONAL);
	}
	// set first and last buffer pointers, a circular log
	//phys_addr = __pa(ctx[ctxid]->buf1[rx_depth-1]);
	//memcpy(ctx[ctxid]->buf1[0]+2*sizeof(unsigned long)+sizeof(int), &phys_addr, sizeof(unsigned long));
	//phys_addr = __pa(ctx[ctxid]->buf1[0]);
	//memcpy(ctx[ctxid]->buf1[rx_depth-1]+3*sizeof(unsigned long)+sizeof(int), &phys_addr, sizeof(unsigned long));
	
	setup_journal_addr(ctxid, ctx[ctxid]->buf1, rx_depth);
#endif
	printk(KERN_ALERT "mr.lkey: %x\n", ctx[ctxid]->mr->lkey);

	ctx[ctxid]->cq = ib_create_cq(ctx[ctxid]->context, poll_cq, NULL, NULL, rx_depth + 1, 0);
	if (!ctx[ctxid]->cq) {
		printk(KERN_ALERT "Couldn't create CQ\n");
		goto clean_mr;
	}

	{
		struct ib_qp_attr attr;
		struct ib_qp_init_attr init_attr = {
			.send_cq = ctx[ctxid]->cq,
			.recv_cq = ctx[ctxid]->cq,
			.cap     = {
				.max_send_wr  = 1,
				.max_recv_wr  = rx_depth,
				.max_send_sge = 1,
				.max_recv_sge = 10
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

	return 0;

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

	return -1;
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
	int i, ret;

	for (i = 0; i < n; ++i)
		if (ret = ib_post_recv(ctx[ctxid]->qp, &wr, &bad_wr)) {
			printk(KERN_CRIT "error ib_post_recv ret %d\n", ret);
			break;
		}

	return i;
}

static int pp_post_recv1(int ctxid, int start, int n)
{
	struct ib_recv_wr *bad_wr;
	int i, ret;
//	printk(KERN_CRIT "pp_post_recv1 start %d n %d\n", start, n);
	for (i = start; i < n+start; ++i) {
		struct ib_sge list[4];
		list[0].lkey = list[1].lkey = list[2].lkey = list[3].lkey = ctx[ctxid]->mr->lkey;
		list[0].addr = ctx[ctxid]->uaddr1[i];
		list[0].length = sizeof(unsigned long);
		list[1].addr = ctx[ctxid]->uaddr2[i];
		list[1].length = sizeof(int);
		list[2].addr = ctx[ctxid]->uaddr4[i];
		list[2].length = sizeof(unsigned long);
		list[3].addr = ctx[ctxid]->uaddr3[i];
		list[3].length = MAX_REQ_SIZE;
/*
		ctx[ctxid]->uaddr1 = ib_dma_map_single(ib_dev, ctx[ctxid]->buf1[i], 2*sizeof(unsigned long)+sizeof(int)+PAGE_SIZE, DMA_BIDIRECTIONAL);
	struct ib_sge list = {
		.addr	= ctx[ctxid]->uaddr1, //(uintptr_t) ctx[ctxid]->buf,
		.length = 2*sizeof(unsigned long)+sizeof(int)+PAGE_SIZE,
		.lkey	= ctx[ctxid]->mr->lkey
	};
*/
		struct ib_recv_wr wr = {
			.wr_id	    = i, //PINGPONG_RECV_WRID,
			.sg_list    = list,
			.num_sge    = 4,
		};

		if (ret = ib_post_recv(ctx[ctxid]->qp, &wr, &bad_wr)) {
			printk(KERN_CRIT "error ib_post_recv ret %d\n", ret);
			break;
		}
	}
	return i-start;
}

static int pp_post_recv2(int ctxid, struct ib_sge *list)
{
	struct ib_recv_wr wr = {
		.wr_id	    = PINGPONG_RECV_WRID,
		.sg_list    = list,
		.num_sge    = 4,
	};
	struct ib_recv_wr *bad_wr;
	int i, ret;

	if (ret = ib_post_recv(ctx[ctxid]->qp, &wr, &bad_wr)) {
		printk(KERN_CRIT "error ib_post_recv ret %d\n", ret);
	}

	return ret;
}
static int pp_post_send(int ctxid)
{
//	printk(KERN_ALERT "pp_post_send :addr%lx, length%x, lkey%x\n", ctx[ctxid]->uaddr, ctx[ctxid]->size, ctx[ctxid]->mr->lkey);
	struct ib_sge list = {
		.addr	= ctx[ctxid]->uaddr, //(uintptr_t) ctx[ctxid]->buf,
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

static int pp_post_send1(int ctxid, int size, u64 uaddr)
{
//	printk(KERN_ALERT "pp_post_send :addr%lx, length%x, lkey%x\n", ctx[ctxid]->uaddr, ctx[ctxid]->size, ctx[ctxid]->mr->lkey);
	struct ib_sge list = {
		.addr	= uaddr, //(uintptr_t) ctx[ctxid]->buf,
		.length = size,
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

int routs[TOTAL_CONNECTIONS];

int routine(void *input)
//int routine(int ctxid, struct ib_device *ib_dev_input)
{
	struct pingpong_dest     my_dest;
	struct pingpong_dest    *rem_dest;	
	char                    *servername = NULL;
	int                      ib_port = 1;
	int                      size = 4096*2;
	enum ib_mtu		 mtu = IB_MTU_2048;
	int                      rx_depth = 11000;
	int                      iters = 0;
	int                      use_event = 0;
	int                      ret;
	int                      rcnt, scnt;	
	int                      sl = 0, rr;
	int			 gidx = -1;
	char			*buf;
     struct timeval          ts_start, ts_end;
        int x = rdma_port_get_link_layer(ib_dev, 1);
	int ctxid = (int)input;
        printk(KERN_ALERT "routine %d IB_SERVER %p LINKLAYER %x\n", ctxid, ib_dev, x);

	buf = kmalloc(128, GFP_KERNEL);
	page_size = 4096;

	ret = pp_init_ctx(ctxid, size, rx_depth, ib_port, use_event);
	if (ret < 0)
		return 1;

	routs[ctxid] = pp_post_recv1(ctxid, 0, ctx[ctxid]->rx_depth/4);
	if (routs[ctxid] < ctx[ctxid]->rx_depth/4) {
		printk(KERN_ALERT "Couldn't post receive (%d)\n", routs[ctxid]);
		return 1;
	}

	if (use_event)
	if (ib_req_notify_cq(ctx[ctxid]->cq, 0)) {
			printk(KERN_ALERT "Couldn't request CQ notification\n");
			return 1;
	}


	if (gidx >= 0) {
		if (ib_query_gid(ctx[ctxid]->context, ib_port, gidx, &my_dest.gid)) {
			printk(KERN_ALERT "can't read sgid of index %d\n", gidx);
			return 1;
		}
	} else
		memset(&my_dest.gid, 0, sizeof my_dest.gid);
        
        ret = ib_query_port(ib_dev, 1, &ctx[ctxid]->portinfo);
	if (ret < 0){
	    printk(KERN_CRIT "ib_query_port failed %d\n", ret);
	    return 1;
	}	

	my_dest.lid = ctx[ctxid]->portinfo.lid;
   	if (!my_dest.lid) {
		printk(KERN_CRIT "Couldn't get local LID\n");
		return 1;
	}

        my_dest.qpn = ctx[ctxid]->qp->qp_num;
        get_random_bytes(&rr, sizeof(int));
        my_dest.psn = rr & 0xffffff;
        //inet_ntop(AF_INET6, &my_dest.gid, gid, sizeof gid);
        printk(KERN_ALERT "  local address:  LID 0x%04x, QPN 0x%06x, PSN 0x%06x\n",
               my_dest.lid, my_dest.qpn, my_dest.psn);

	rem_dest = pp_server_exch_dest(ctxid, ib_port, mtu, sl, &my_dest, gidx);


        if (!rem_dest)
                return 1;

        printk(KERN_ALERT "routine %d done remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x, PORT %d\n",
			ctxid, rem_dest->lid, rem_dest->qpn, rem_dest->psn, ib_port);
	return 0;

}

int ibv_recvmsg(int ctxid, void *addr, int size) {
	struct ib_wc wc[1];
	int ne, i, ret = 0;
#ifdef DEBUG_IBV
	printk(KERN_CRIT "ibv_recvmsg %d addr %llx size %d uaddr %llx\n", ctxid, addr, size, ctx[ctxid]->uaddr);
#endif
	ctx[ctxid]->pending = PINGPONG_RECV_WRID;

	do {
		ne = ib_poll_cq(ctx[ctxid]->cq, 1, wc);
		if (ne < 0) {
			printk(KERN_ALERT "poll CQ failed %d\n", ne);
			return -1;
		}
	} while (ne < 1);
	for (i = 0; i < ne; ++i) {
#ifdef DEBUG_IBV
		printk(KERN_CRIT "ibv_recvmsg %d Got wc status = %d, content = %d ne %d byte_len %d\n", ctxid, (int)wc[i].status, (int)wc[i].wr_id, ne, (int)wc[i].byte_len);
#endif
		if (wc[i].status != IB_WC_SUCCESS) {
			printk(KERN_ALERT "recvmsg pid %d Failed status (%d) for wr_id %d\n",
					current->pid, wc[i].status, (int) wc[i].wr_id);
			return -1;
		}	
	routs[ctxid]--;
	if ((wc[i].wr_id % (ctx[ctxid]->rx_depth/4)) == 0) {
	//if (--routs <= 1) {
//#ifdef DEBUG_IBV
//		printk(KERN_CRIT "add more receive buffers %d id %d\n", routs, wc[0].wr_id);
//#endif
		routs[ctxid] += pp_post_recv1(ctxid, (wc[i].wr_id + (ctx[ctxid]->rx_depth/4)) % TOTAL_JOURNAL_SIZE, ctx[ctxid]->rx_depth/4);
//#ifdef DEBUG_IBV
//		printk(KERN_CRIT "add more receive buffers %d start %d\n", routs, (wc[i].wr_id + (ctx[ctxid]->rx_depth/4)) % ctx[ctxid]->rx_depth);
//#endif
//		if (routs < ctx[ctxid]->rx_depth) {
//			printk(KERN_ALERT
//					"Couldn't post receive (%d)\n",
//					routs);
//			return -1;
//		}
	}
}

	return wc[0].wr_id;
}

int ibv_sendmsg(int ctxid, void *addr, int size) {
	
	struct ib_wc wc[1];
	int ne, i, ret = 0;
	//ctx[ctxid]->buf = addr;
	//ctx[ctxid]->size = size;
	//ctx[ctxid]->mr = ib_get_dma_mr(ctx[ctxid]->pd, IB_ACCESS_REMOTE_READ | IB_ACCESS_LOCAL_WRITE |IB_ACCESS_REMOTE_WRITE);
	u64 uaddr = ib_dma_map_single(ib_dev, addr, size, DMA_BIDIRECTIONAL);
//	printk(KERN_CRIT "ibv_sendmsg addr %llx size %d\n", addr, size);
	ctx[ctxid]->pending |= PINGPONG_SEND_WRID;
	if (ret = pp_post_send1(ctxid, size, uaddr)) {
		printk(KERN_ALERT "Couldn't post send\n");
		return 0;
	}
	do {
		ne = ib_poll_cq(ctx[ctxid]->cq, 1, wc);
		if (ne < 0) {
			printk(KERN_ALERT "poll CQ failed %d\n", ne);
			return 1;
		}
	} while (ne < 1);
	//			printk(KERN_ALERT "BBB\n");	
	for (i = 0; i < ne; ++i) {
//		printk(KERN_CRIT "Got wc status = %d, content = %d ne %d byte_len %d\n", (int)wc[i].status, (int)wc[i].wr_id, ne, (int)wc[i].byte_len);
		if (wc[i].status != IB_WC_SUCCESS) {
			printk(KERN_ALERT "sendmsg Failed status (%d) for wr_id %d\n",
					wc[i].status, (int) wc[i].wr_id);
			return 1;
		}	
		switch ((int) wc[i].wr_id) {
			case PINGPONG_SEND_WRID:
				break;

			case PINGPONG_RECV_WRID:
				break;

			default:
				printk(KERN_ALERT "Completion for unknown wr_id %d\n",
						(int) wc[i].wr_id);
				return 0;
		}

	}
//	printk(KERN_CRIT "ibv_sendmsg addr %llx size %d ret %d\n", addr, size, ret);
	return ret;
}

static void ibv_add_one(struct ib_device *device)
{
	int i;
	ib_dev = device;
#ifdef SECBAK_IB
	printk(KERN_CRIT "start routine_1\n");
	ctx1 = (struct pingpong_context_1 **)kmalloc(TOTAL_CONNECTIONS*sizeof(struct pingpong_context_1 *), GFP_KERNEL);
	ctx_pd_1 = ib_alloc_pd(device);
	if (!ctx_pd_1) {
		printk(KERN_ALERT "Couldn't allocate PD\n");
	}
	for (i = 0; i < TOTAL_CONNECTIONS; i++)
		kthread_run(routine_1, (void*)i, "ib routine_1");
#endif
	printk(KERN_CRIT "start routine\n");
	ctx = (struct pingpong_context **)kmalloc(TOTAL_CONNECTIONS*sizeof(struct pingpong_context *), GFP_KERNEL);
	ctx_pd = ib_alloc_pd(device);
	if (!ctx_pd) {
		printk(KERN_ALERT "Couldn't allocate PD\n");
	}
	for (i = 0; i < TOTAL_CONNECTIONS; i++)
		kthread_run(routine, (void*)i, "ib routine");
	printk(KERN_CRIT "done routine\n");
	//	routine_1(1, device);
}

static void ibv_remove_one(struct ib_device *device)
{
	return;
}

static void ibv_release_dev(struct device *dev)
{
	
}

static int __init ibv_init_module(void)
{
	int ret;

	BUILD_BUG_ON(FIELD_SIZEOF(struct ib_wc, wr_id) < sizeof(void *));

	struct ib_api_t *ib_api = (struct ib_api_t *)kmalloc(sizeof(struct ib_api_t), GFP_KERNEL);
	ib_api->sendmsg = ibv_sendmsg;
	ib_api->recvmsg = ibv_recvmsg;
	ib_api->network_worker_func_sync = network_worker_func_sync_ibverbs;

	setup_ibverbs(ib_api);
	atomic_set(&global_reqid, 0);
	int i;
	for (i = 0; i < TOTAL_CONNECTIONS; i++)
		spin_lock_init(&send_req_lock[i]);

	ret = class_register(&ibv_class);
	if (ret) {
		pr_err("couldn't register class ibv\n");
		return ret;
	}

	ret = ib_register_client(&ibv_client);
	if (ret) {
		pr_err("couldn't register IB client\n");
		class_unregister(&ibv_class);
		return ret;
	}

	return 0;
}

static void __exit ibv_cleanup_module(void)
{
	ib_unregister_client(&ibv_client);
	class_unregister(&ibv_class);
}


module_init(ibv_init_module);
module_exit(ibv_cleanup_module);

