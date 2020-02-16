/*
 * Copyright (c) 2016-2020 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef HAVE_CLIENT_H
#define HAVE_CLIENT_H

#include <lego/spinlock.h>
#include <lego/atomic.h>
//#include <lego/wait.h>
#include <net/arch/cc.h>
#include <lego/socket.h>

#define DEBUG_SHINYEH

#define MAX_FIT_NUM 4

#define FIT_USERSPACE_FLAG 1
#define FIT_KERNELSPACE_FLAG 0
#define FIT_LINUX_PAGE_OFFSET 0x00000fff

#define CIRCULAR_BUFFER_LENGTH 256

#define MAX_NODE	CONFIG_FIT_NR_NODES

#define MAX_NODE_BIT 5

#define LISTEN_PORT 18500

/*
 * QPs between each node pair
 * Configured at compile time.
 */
#define NUM_PARALLEL_CONNECTION			(CONFIG_FIT_NR_QPS_PER_PAIR)

#define RECV_DEPTH					(256)
#define CONNECTION_ID_PUSH_BITS_BASED_ON_RECV_DEPTH	(8)

#ifdef CONFIG_SOCKET_O_IB
# define GET_NODE_ID_FROM_POST_RECEIVE_ID(id)	((id>>8) / (NUM_PARALLEL_CONNECTION + 1))
#else
# define GET_NODE_ID_FROM_POST_RECEIVE_ID(id)	((id>>8) / NUM_PARALLEL_CONNECTION)
#endif

#define GET_POST_RECEIVE_DEPTH_FROM_POST_RECEIVE_ID(id) (id&0x000000ff)

#define LID_SEND_RECV_FORMAT "0000:0000:000000:000000:00000000000000000000000000000000"
#ifdef CONFIG_SOCKET_O_IB
#define MAX_CONNECTION MAX_NODE * (NUM_PARALLEL_CONNECTION + 1) //Assume that MAX_CONNECTION is smaller than 256
#else
#define MAX_CONNECTION MAX_NODE * NUM_PARALLEL_CONNECTION //Assume that MAX_CONNECTION is smaller than 256
#endif
#define MAX_PARALLEL_THREAD 64
#define WRAP_UP_NUM_FOR_WRID 256 //since there are 64 bits in wr_id, we are going to use 9-12 bits to do thread id waiting passing
#define WRAP_UP_NUM_FOR_CIRCULAR_ID 256
#define WRAP_UP_NUM_FOR_WAITING_INBOX 256
#define WRAP_UP_NUM_FOR_TYPE 65536 //since there are 64 bits in wr_id, we are going to use 9-12 bits to do thread id waiting passing
//const int MAX_NODE = 4;
#define POST_RECEIVE_CACHE_SIZE 256
#define SERVER_ID 0

#ifdef CONFIG_FIT_MAX_OUTSTANDING_SEND
# define MAX_OUTSTANDING_SEND	CONFIG_FIT_MAX_OUTSTANDING_SEND
#else
# error "Please config a number."
#endif

#define FIT_LINUX_PAGE_OFFSET 0x00000fff

#define HIGH_PRIORITY 4
#define LOW_PRIORITY 0
#define KEY_PRIORITY 8
#define CONGESTION_ALERT 2
#define CONGESTION_WARNING 1
#define CONGESTION_FREE 0

//MULTICAST RELATED
#define MAX_MULTICAST_HOP 16
#define MAX_LENGTH_OF_ATOMIC 256

// IMM_ related things
#define NUM_OF_CORES 2
//Model 2 --> 2-6-24 (Send-recv-opcode, port, offset)
#define IMM_SEND_REPLY_SEND	0x80000000
#define IMM_SEND_REPLY_RECV	0x40000000
#define IMM_ACK			0x20000000
#define IMM_REPLY_W_EXTRA_BITS	0x10000000
#define IMM_PORT_PUSH_BIT	24
#define IMM_GET_PORT_NUMBER(imm) (imm<<2)>>26
#define IMM_GET_OFFSET		0x00ffffff
#define IMM_GET_REPLY_INDICATOR_INDEX	0x000fffff
#define IMM_SET_PRIVATE_BITS(bits)	(bits << 20)
#define IMM_GET_PRIVATE_BITS(imm)	((imm >> 20) & 0xff)
#define REPLY_PRIVATE_BITS_CNT	8
//#define IMM_NODE_BITS		24
//#define IMM_GET_NODE_ID(imm)	(imm>>24)&0xff
#define IMM_GET_OPCODE		0x0f000000
#define IMM_GET_OPCODE_NUMBER(imm) (imm<<4)>>28
#define IMM_DATA_BIT 32
#define IMM_NUM_OF_SEMAPHORE 64
#define IMM_MAX_PORT 64
#define IMM_RING_SIZE 1024*1024*4
#define IMM_MAX_SIZE IMM_RING_SIZE/NUM_OF_CORES
#define IMM_SEND_SLEEP_SIZE_THRESHOLD 40960
#define IMM_SEND_SLEEP_TIME_THRESHOLD 20
//#define IMM_PORT_CACHE_SIZE 128
//#define RDMA_RING_SIZE 128
#define IMM_PORT_CACHE_SIZE 1024*1024*4
#define RDMA_RING_SIZE 1024*1024*4
#define IMM_ACK_FREQ 1024*512
//#define IMM_ACK_PORTION 8

//Lock related
#define FIT_MAX_LOCK_NUM 64
#define FIT_MAX_WAIT_QUEUE 64

#define SEND_REPLY_WAIT -101
#define SEND_REPLY_EMPTY -102
#define SEND_REPLY_PORT_NOT_OPENED -103
#define SEND_REPLY_PORT_IS_FULL -104
#define SEND_REPLY_SIZE_TOO_BIG -105
#define SEND_REPLY_FAIL -106
#define SEND_REPLY_ACK 0

enum mode {
	M_WRITE,
	M_READ,
	FIT_SEND_MESSAGE_IMM_ONLY,
	FIT_SEND_ACK_IMM_ONLY,
	FIT_SEND_MESSAGE_HEADER_AND_IMM,
	FIT_SEND_MESSAGE_HEADER_ONLY
};
enum lock_state{
	LOCK_AVAILABLE,
	LOCK_GET_LOCK,
	UNLOCK_ALREADY_ARRIVED,
	WAIT_FOR_UNLOCK
//	LOCK_USED,
//	LOCK_AVAILABLE,
//	LOCK_LOCK,
//	LOCK_ASSIGNED
};

struct ibapi_post_receive_intermediate_struct
{
	uintptr_t header;
	uintptr_t msg;
};

struct ibapi_header{
	uint32_t        src_id;
	uint64_t        reply_addr;
	uint64_t        reply_indicator_index;
	uint32_t        length;
	int             priority;
	int             type;
};
struct fit_ibv_mr {
	//struct ib_device	*context;
	//struct ib_pd		*pd;
	void			*addr;
	size_t			length;
	//uint32_t		handle;
	uint32_t		lkey;
	uint32_t		rkey;
	uint32_t		node_id;
};

#define FIT_PAGE_SHIFT		12
#define FIT_PAGE_SIZE			(1UL << FIT_PAGE_SHIFT)
struct max_reply_msg {
	char msg[FIT_PAGE_SIZE];
	int length;
};

struct atomic_struct{
	void	*vaddr;
	size_t	len;
};

struct ask_mr_reply_form{
	struct fit_ibv_mr reply_mr;
	uint64_t permission;
	uint64_t op_code;
};

struct mr_request_form{
	struct fit_ibv_mr request_mr;
	struct fit_ibv_mr copyto_mr;
	uint64_t offset;
	uint64_t copyto_offset;
	uint64_t size;
	uint64_t op_code;
};

enum register_application_port_ret{
	REG_FAIL = -1,
	REG_PORT_TOO_LARGE = -2,
	REG_SIZE_TOO_LARGE = -3,
	REG_NAME_TOO_LONG = -4,
	REG_PORT_OCCUPIED = -5,
	REG_DO_QUERY_FIRST = -6
};

struct app_reg_port{
	struct fit_ibv_mr ring_mr;
//	unsigned int port;

	unsigned int node;
//	uint64_t hash_key;
	uint64_t port_node_key;
	void *addr;
//	char name[32];
//	struct hlist_node hlist;
	int remote_imm_ring_index;
	spinlock_t remote_imm_offset_lock;
	int last_ack_index;
	spinlock_t last_ack_index_lock;
};

struct imm_ack_form{
	int node_id;
	unsigned int designed_port;
	int ack_offset;
};

#if 0
struct fit_lock_form{
	int lock_num;
	struct fit_ibv_mr lock_mr;
	uint64_t ticket_num;
};
typedef struct fit_lock_form remote_spinlock_t;

struct fit_lock_reserve_form{
	int lock_num;
	uint64_t ticket_num;
};

struct fit_lock_queue_element{
	uint64_t        inbox_addr;
	uint64_t        reply_indicator_index;	
	uint32_t        src_id;
	unsigned int	ticket_num;
	int	lock_num;
	int	state;
	int	tar_lock_index;
	struct hlist_node hlist;
};
#endif

enum mr_request_op_code{
	OP_REMOTE_MEMSET=0,
	OP_REMOTE_MEMCPY=1,
	OP_REMOTE_REREGISTER=2,
	OP_REMOTE_DEREGISTER=3,
	OP_REMOTE_FREE=4,
	OP_REMOTE_MEMMOV=5
};

enum permission_mode{
	MR_READ_FLAG=0x01,
	MR_WRITE_FLAG=0x02,
	MR_SHARE_FLAG=0x04,
	MR_ADMIN_FLAG=0x08,
	MR_ATOMIC_FLAG=0x10,
	MR_ASK_SUCCESS=0,
	MR_ASK_REFUSE=1,
	MR_ASK_UNPERMITTED=2,
	MR_ASK_HANDLER_ERROR=3,
	MR_ASK_UNKNOWN=4
};

struct send_and_reply_format
{       
        uint32_t        src_id;
        uint64_t        inbox_addr;
	uint64_t	reply_indicator_index;
        uint32_t        length;
	int		type;
        char            *msg;
	int		priority;
	struct list_head list;
};

enum {
	MSG_MR,
	MSG_DONE,
	MSG_NODE_JOIN,
	MSG_NODE_JOIN_UD,
	MSG_SERVER_SEND,
	MSG_CLIENT_SEND,
	MSG_CREATE_LOCK,
	MSG_CREATE_LOCK_REPLY,
	MSG_RESERVE_LOCK,
	MSG_ASSIGN_LOCK,
	MSG_UNLOCK,
	MSG_ASK_LOCK,
	MSG_ASK_LOCK_REPLY,
	MSG_GET_REMOTEMR,
	MSG_GET_REMOTE_ATOMIC_OPERATION,
	MSG_GET_REMOTEMR_REPLY,
	MSG_GET_SEND_AND_REPLY_1,
	MSG_GET_SEND_AND_REPLY_1_UD,
	MSG_GET_SEND_AND_REPLY_2,
	MSG_GET_ATOMIC_START,
	MSG_GET_ATOMIC_MID,
	MSG_GET_ATOMIC_REPLY,
	MSG_GET_ATOMIC_SINGLE_START,
	MSG_GET_ATOMIC_SINGLE_MID,
	MSG_ASK_MR_1,
	MSG_ASK_MR_2,
	MSG_MR_REQUEST,
	MSG_GET_SEND_AND_REPLY_OPT_1,
	MSG_GET_SEND_AND_REPLY_OPT_2,
	MSG_GET_INTERNAL_EXCHANGE,
	MSG_DIST_BARRIER,
	MSG_GET_FINISH,
	MSG_QUERY_PORT_1,
	MSG_QUERY_PORT_2,
	MSG_PASS_LOCAL_IMM,
	MSG_DO_RC_POST_RECEIVE,
	MSG_DO_UD_POST_RECEIVE,
	MSG_DO_ACK_INTERNAL,
	MSG_DO_ACK_REMOTE,
	MSG_SOCK_DO_ACK_INTERNAL,
	MSG_SOCK_DO_ACK_REMOTE,
	MSG_SEND_RDMA_RING_MR
};

enum {
	PINGPONG_RECV_WRID = 1,
	PINGPONG_SEND_WRID = 2,
};

struct fit_ah_combined
{
	int			qpn;
	int			node_id;
	int			qkey;
	int			dlid;
};

//Related to remote imm-write

struct imm_message_metadata
{
	uint32_t source_node_id;
        uintptr_t reply_addr;
	uint32_t reply_rkey;
	uint32_t reply_indicator_index;
	uint32_t size;
};

struct imm_header_from_cq_to_port
{       
        uint32_t        source_node_id;
	uint32_t	offset;
	struct list_head list;
};

struct _lego_context_pad {
	char x[0];
} ____cacheline_aligned_in_smp;

#define CTX_PADDING(name)	struct _lego_context_pad name;

struct lego_context {
	struct ib_context	*context;
	struct ib_comp_channel *channel;
	struct ib_pd		*pd;
	struct ib_cq		**cq; // one completion queue for all qps
	atomic_t *cq_block;
    	//wait_queue_head_t *cq_block_queue;
	struct ib_cq		**send_cq;
	struct ib_qp		**qp; // multiple queue pair for multiple connections

#ifdef CONFIG_SOCKET_O_IB
	/* socket related */
	struct ib_qp		**sock_qp;
	struct ib_cq		**sock_send_cq;
	struct ib_cq		*sock_recv_cq;
#endif

	struct ib_qp		*qpUD;// one UD qp for all the send-reply connections
	struct ib_cq		*cqUD;
	struct ib_cq		*send_cqUD;
	struct ib_ah 		**ah;
	struct fit_ah_combined *ah_attrUD;

	int recv_numUD;
	spinlock_t connection_lockUD;

	int			 send_flags;
	int			 rx_depth;
	struct ib_port_attr     portinfo;
	int 			num_connections;
	int             num_node;
	int             num_parallel_connection;
	atomic_t             *num_alive_connection;
	atomic_t		num_alive_nodes;
	struct ib_mr *proc;
	int node_id;

	int			*send_cq_queued_sends;
	int *recv_num;
	atomic_t *atomic_request_num;
	atomic_t parallel_thread_num;
    
	enum s_state {
		SS_INIT,
		SS_MR_SENT,
	        SS_RDMA_WAIT,
		SS_RDMA_SENT,
		SS_DONE_SENT,
	        SS_MSG_WAIT,
	        SS_MSG_SENT,
	        SS_GET_REMOTE_WAIT,
	        SS_GET_REMOTE_DONE,
	        MSG_GET_SEND_AND_REPLY
	} *send_state;

	enum r_state {
		RS_INIT,
		RS_MR_RECV,
        RS_RDMA_WAIT,
        RS_RDMA_RECV,
		RS_DONE_RECV
	} *recv_state;
    
	atomic_t send_reply_wait_num;

	struct atomic_struct **atomic_buffer;
	int *atomic_buffer_total_length;
	int *atomic_buffer_cur_length;

	void **local_rdma_recv_rings;
	int *remote_rdma_ring_mrs_offset;
	int *remote_last_ack_index;
	spinlock_t *remote_imm_offset_lock;
	struct fit_ibv_mr *local_rdma_ring_mrs;
	int *local_last_ack_index;
	spinlock_t *local_last_ack_index_lock;
	struct fit_ibv_mr *remote_rdma_ring_mrs;

#ifdef CONFIG_SOCKET_O_IB
	void **local_sock_rdma_recv_rings;
	int *remote_sock_rdma_ring_mrs_offset;
	int *remote_sock_last_ack_index;
	spinlock_t *remote_sock_imm_offset_lock;
	struct fit_ibv_mr *local_sock_rdma_ring_mrs;
	int *local_sock_last_ack_index;
	spinlock_t *local_sock_last_ack_index_lock;
	struct fit_ibv_mr *remote_sock_rdma_ring_mrs;
#endif

   	int (*send_handler)(char *addr, uint32_t size, int sender_id);
	int (*send_reply_handler)(char *input_addr, uint32_t input_size, char *output_addr, uint32_t *output_size, int sender_id);
	int (*send_reply_opt_handler)(char *input_buf, uint32_t size, void **output_buf, uint32_t *output_size, int sender_id);
	int (*send_reply_rdma_imm_handler)(int sender_id, void *msg, uint32_t size, uint32_t inbox_addr, uint32_t inbox_rkey, uint32_t reply_indicator_index);

	atomic_t* connection_congestion_status;
	
	struct ibapi_header *first_packet_header, *other_packet_header;
	int *connection_id_array;
	uintptr_t *length_addr_array;
	void **output_header_addr;
	void **first_header_addr;
	void **mid_addr;

	//Needed for cross-nodes-implementation
        atomic_t alive_connection;
	atomic_t num_completed_threads;

	//Related to barrier
	atomic_t dist_barrier_counter;
	
	CTX_PADDING(_pad1_)
	spinlock_t imm_waitqueue_perport_lock[IMM_MAX_PORT];
	struct imm_header_from_cq_to_port imm_waitqueue_perport[IMM_MAX_PORT];
	int imm_perport_reg_num[IMM_MAX_PORT];//-1 no registeration, 0 up --> how many

#ifdef CONFIG_SOCKET_O_IB
	struct imm_header_from_cq_to_port sock_imm_waitqueue_perport[SOCK_MAX_LISTEN_PORTS];
	spinlock_t sock_imm_waitqueue_perport_lock[SOCK_MAX_LISTEN_PORTS];
#endif
	
	CTX_PADDING(_pad2_)
	spinlock_t	indicators_lock;
	void		*reply_ready_indicators[IMM_NUM_OF_SEMAPHORE];
	DECLARE_BITMAP(reply_ready_indicators_bitmap, IMM_NUM_OF_SEMAPHORE);

	CTX_PADDING(_pad3_)

#ifdef ADAPTIVE_MODEL
	wait_queue_head_t *imm_inbox_block_queue;
#endif
#ifdef SCHEDULE_MODEL
	struct task_struct **thread_waiting_for_reply;
#endif

	atomic_t imm_cache_perport_work_head[IMM_MAX_PORT];
	atomic_t imm_cache_perport_work_tail[IMM_MAX_PORT];

	atomic_t *connection_count;
	
	//Lock related
	atomic_t lock_num;
	struct fit_lock_form *lock_data;
	struct fit_lock_queue_element *lock_queue;
};
typedef struct lego_context ppc;

struct lego_dest {
	int node_id;
	int lid;
	int qpn;
	int psn;
	union ib_gid gid;
};

struct fit_data{
	char server_information_buffer[sizeof(LID_SEND_RECV_FORMAT)];
};

struct thread_pass_struct{
	ppc *ctx;
	struct ib_cq *target_cq;
	char *msg;
	struct send_and_reply_format *sr_request;
	int recvcq_id;
};

#endif
