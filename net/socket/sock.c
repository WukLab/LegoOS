/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file implements all socket syscalls:
 * 	socket, bind, listen, accept, connect
 * 	send, recv, sendto, recvfrom
 * 	setsockopt, getsockopt
 * and all socket file ops
 */

#include <lego/syscalls.h>
#include <lego/socket.h>
#include <lego/atomic.h>
#include <processor/processor.h>
#include <lego/net.h>
#include <lego/fit_ibapi.h>
#include <lego/files.h>
#include <processor/fs.h>
#include <lego/spinlock.h>
#include <lego/hashtable.h>
#include <lego/comp_storage.h>
#include <lego/delay.h>
#include <lego/time.h>
#include <lego/timer.h>
#include <processor/vnode.h>

#ifdef CONFIG_DEBUG_SOCKET
#define sock_debug(fmt, ...) \
	pr_debug("%s():%d " fmt, __func__, __LINE__, __VA_ARGS__)
#else
static inline void sock_debug(const char *fmt, ...) { }
#endif



atomic_t global_flow_id;

u32 ip2saddr[TOTAL_PHYS_NODE];
int ipid2nodeid[TOTAL_PHYS_NODE];

struct list_head global_socket_list;
spinlock_t global_sock_list_lock;
char *global_buffer_for_no_sock;
int global_buffer_for_no_sock_size;

static struct hlist_head port_hash[MAX_NODE][SOCK_PORT_HASH_BUCKET_BITS];
static spinlock_t port_hash_lock[MAX_NODE];

static DECLARE_BITMAP(sock_local_port_bitmap, MAX_KERNEL_SOCK_PORTS);
static DEFINE_SPINLOCK(sock_local_port_bitmap_lock);
static DECLARE_BITMAP(fit_local_port_bitmap, SOCK_MAX_LISTEN_PORTS);
static DEFINE_SPINLOCK(fit_local_port_bitmap_lock);

void init_sock_ips(void) {
	// IP addr 128.46.115.31
	ip2saddr[0] = 0x1f732e80;
	// IP addr 128.46.115.32
	ip2saddr[1] = 0x20732e80;
	// IP addr 128.46.115.33
	ip2saddr[2] = 0x21732e80;
	// IP addr 128.46.115.34
	ip2saddr[3] = 0x22732e80;
	// IP addr 128.46.115.35
	ip2saddr[4] = 0x23732e80;
	// IP addr 128.46.115.36
	ip2saddr[5] = 0x24732e80;
	// IP addr 128.46.115.37
	ip2saddr[6] = 0x25732e80;
	// IP addr 128.46.115.38
	ip2saddr[7] = 0x26732e80;
	// IP addr 128.46.115.140
	ip2saddr[8] = 0x8c732e80;
	// IP addr 128.46.115.141
	ip2saddr[9] = 0x8d732e80;
	// IP addr 128.46.115.142
	ip2saddr[10] = 0x8e732e80;
	// IP addr 128.46.115.143
	ip2saddr[11] = 0x8f732e80;
	// IP addr 128.46.115.144
	ip2saddr[12] = 0x90732e80;
	// IP addr 128.46.115.145
	ip2saddr[13] = 0x91732e80;
	// IP addr 128.46.115.19
	ip2saddr[14] = 0x13732e80;
	// IP addr 128.46.115.20
	ip2saddr[15] = 0x14732e80;
	// IP addr 128.46.115.21
	ip2saddr[16] = 0x15732e80;
	// IP addr 128.46.115.22
	ip2saddr[17] = 0x16732e80;
	// IP addr 128.46.115.23
	ip2saddr[18] = 0x17732e80;
	// IP addr 128.46.115.24
	ip2saddr[19] = 0x18732e80;

	ipid2nodeid[0] = -1;
	ipid2nodeid[1] = -1;
	ipid2nodeid[2] = -1;
	ipid2nodeid[3] = -1;
	ipid2nodeid[4] = -1;
	ipid2nodeid[5] = -1;
	ipid2nodeid[6] = -1;
	ipid2nodeid[7] = -1;
	ipid2nodeid[8] = -1;
	ipid2nodeid[9] = 2;
	ipid2nodeid[10] = -1;
	ipid2nodeid[11] = -1;
	ipid2nodeid[12] = -1;
	ipid2nodeid[13] = 0;
	ipid2nodeid[14] = -1;
	ipid2nodeid[15] = 1;
	ipid2nodeid[16] = -1;
	ipid2nodeid[17] = -1;
	ipid2nodeid[18] = -1;
	ipid2nodeid[19] = -1;
}

#ifdef CONFIG_VNODE
int get_FIT_node_id_from_saddr(u32 saddr)
{	
	struct vnode_struct *vnode;
	vnode = ip_find_vnode(saddr);
	return vnode->p_nid;
}

u32 get_saddr_from_fit_node_id(int node_id)
{
	/* at this stage, node_id and vid is the same */
	struct vnode_struct *vnode;
	vnode = vid_find_vnode(node_id);
	return (u32)vnode->ip;
}
#else
int get_FIT_node_id_from_saddr(u32 saddr)
{
	int i;
	
	sock_debug("%s: saddr %x\n", __func__, saddr);
	for (i = 0; i < TOTAL_PHYS_NODE; i++) {
		if (ip2saddr[i] == saddr)
			break;
	}
	sock_debug("%s: saddr %x node %d\n", __func__, saddr, i);
	
	if (i == TOTAL_PHYS_NODE || ipid2nodeid[i] == -1) {
		pr_crit("wrong socket address!\n");
		return SOCK_FAIL;
	}

	return ipid2nodeid[i];
}

u32 get_saddr_from_fit_node_id(int node_id)
{
	int i;

	for (i = 0; i < TOTAL_PHYS_NODE; i++) {
		if (ipid2nodeid[i] == node_id) {
			return ip2saddr[i];
		}
	}

	return -1;
}
#endif

int get_and_insert_new_local_port(int target_node)
{
	int new_port, new_fit_port;
	struct sock_port_to_ib_port *new_entry;

	/* search for the next available port for target node */
	spin_lock(&sock_local_port_bitmap_lock);
	new_port = find_first_zero_bit(sock_local_port_bitmap, 1);
	set_bit(new_port, sock_local_port_bitmap);
	spin_unlock(&sock_local_port_bitmap_lock);
	new_port += SOCK_KERNEL_START_PORT_NUM;
	sock_debug("%s: targetnode %d new port %d\n", __func__, target_node, new_port);

	/* search for the next fit internal port */
	spin_lock(&fit_local_port_bitmap_lock);
	new_fit_port = find_first_zero_bit(fit_local_port_bitmap, 1);
	set_bit(new_fit_port, fit_local_port_bitmap);
	spin_unlock(&fit_local_port_bitmap_lock);
	sock_debug("%s: targetnode %d new port %d fitport %d\n", __func__, target_node, new_port, new_fit_port);

	/* insert port map to hash table */
	new_entry = (struct sock_port_to_ib_port *)kmalloc(sizeof(struct sock_port_to_ib_port), GFP_KERNEL);
	new_entry->fit_port = new_fit_port;
	hash_add(port_hash[target_node], &new_entry->hlist, new_port);

	return new_port;
}

int set_internal_port(int target_node, int port)
{
	int new_fit_port;
	struct sock_port_to_ib_port *new_entry;

	/* search for the next fit internal port */
	spin_lock(&fit_local_port_bitmap_lock);
	new_fit_port = find_first_zero_bit(fit_local_port_bitmap, 1);
	set_bit(new_fit_port, fit_local_port_bitmap);
	spin_unlock(&fit_local_port_bitmap_lock);

	/* insert port map to hash table */
	new_entry = (struct sock_port_to_ib_port *)kmalloc(sizeof(struct sock_port_to_ib_port), GFP_KERNEL);
	new_entry->fit_port = new_fit_port;
	hash_add(port_hash[target_node], &new_entry->hlist, port);

	sock_debug("%s target_node %d port %d internal port %d\n",
			__func__, target_node, port, new_fit_port);
	return new_fit_port;
}

int get_internal_port(int target_node, int port)
{
	int internal_port_num = -1;
	struct sock_port_to_ib_port *entry;

	spin_lock(&port_hash_lock[target_node]);
	hash_for_each_possible(port_hash[target_node], entry, hlist, port) {
		internal_port_num = entry->fit_port;
	}
	spin_unlock(&port_hash_lock[target_node]);

	sock_debug("%s target_node %d port %d internal port %d\n",
			__func__, target_node, port, internal_port_num);

	if (internal_port_num == -1)
		pr_crit("%s Error: cannot find port %d\n", __func__, port);
	return internal_port_num;
}


SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
	int fd;
	struct file *f;
	struct lego_socket *sock;

	fd = sys_open("sock/socket", O_RDWR | O_CREAT, 0);
	if (fd < 0) {
		return fd;
	}

	sock_debug("%s family %d type %x protocol %d fd %d\n",
			__func__, family, type, protocol, fd);

	f = fdget(fd);
	if (!f)
		return -ENFILE;

	f->private_data = kmalloc(sizeof(struct lego_socket), GFP_KERNEL);
	sock = (struct lego_socket *)f->private_data;

	memset(sock, 0, sizeof(struct lego_socket));
	sock->status = SOCK_CREATED;
	sock->sa_family = family;
	sock->type = type;
	sock->fd = fd;
	sock->file = f;
	INIT_LIST_HEAD(&sock->recvd_conn_list.list);

	spin_lock(&global_sock_list_lock);
	list_add_tail(&sock->list, &global_socket_list);
	spin_unlock(&global_sock_list_lock);

	sock_debug("%s created sock %p fd %d f %p\n", __func__, sock, fd, f);

	return fd;
}

/*
 *	set socket TCP options.
 */
static int tcp_setsockopt(struct lego_socket *sock, int level,
		int optname, char __user *optval, unsigned int optlen)
{
	struct sock_options *sk = &(sock->sk_opt);
	int val;
	int err = 0;

	if (optlen < sizeof(int))
		return -EINVAL;

	if (copy_from_user(&val, optval, sizeof(int)))
		return -EFAULT;

	switch (optname) {
		case TCP_NODELAY:
			if (val) {
				sk->tcp_nodelay = 1;
			} else {
				sk->tcp_nodelay = 0;
			}
			break;
		default:
			err = -ENOPROTOOPT;
			break;
	}

	return err;
}

/*
 *	get socket TCP options.
 */
static int tcp_getsockopt(struct lego_socket *sock, int level,
		int optname, char __user *optval, int __user *optlen)
{
	struct sock_options *sk = &(sock->sk_opt);
	int len;
	int val;
	int err = 0;

	if (copy_from_user(&len, optlen, sizeof(int)))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	switch (optname) {
		case TCP_NODELAY:
			val = sk->tcp_nodelay;
			break;
		default:
			err = -ENOPROTOOPT;
			break;
	}

	if (len > sizeof(int))
		len = sizeof(int);
	if (copy_to_user(optval, &val, len))
		return -EFAULT;

	return err;
}

/*
 *	Limited set of socket opt implemented here
 *	not a generic implementation!
 */
int sock_setsockopt(struct lego_socket *sock, int level, int optname,
		    char __user *optval, unsigned int optlen)
{
	struct sock_options *sk = &(sock->sk_opt);
	int val;
	int valbool;
	int ret = 0;

	if (optlen < sizeof(int))
		return -EINVAL;

	if (copy_from_user(&val, optval, sizeof(int)))
		return -EFAULT;

	valbool = val ? 1 : 0;

	switch (optname) {
		case SO_REUSEADDR:
			sk->sk_reuse = (valbool ? SK_CAN_REUSE : SK_NO_REUSE);
			break;
		case SO_REUSEPORT:
			sk->sk_reuseport = valbool;
			break;
		case SO_ERROR:
			ret = -ENOPROTOOPT;
			break;
		default:
			ret = -ENOPROTOOPT;
			break;
	}
	return ret;
}

/*
 *  	Recover an error report and clear atomically
 */

static inline int sock_error(struct sock_options *sk)
{
	int err;
	if (likely(!sk->sk_err))
		return 0;
	err = xchg(&sk->sk_err, 0);
	return -err;
}

/*
 *	Limited set of socket opt implemented here
 *	not a generic implementation!
 */
int sock_getsockopt(struct lego_socket *sock, int level, int optname,
		    char __user *optval, int __user *optlen)
{
	struct sock_options *sk = &(sock->sk_opt);
	int len;
	int val;

	if (copy_from_user(&len, optlen, sizeof(int)))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	switch (optname) {

	case SO_REUSEADDR:
		val = sk->sk_reuse;
		break;

	case SO_REUSEPORT:
		val = sk->sk_reuseport;
		break;

	case SO_ERROR:
		val = -sock_error(sk);
		if (val == 0)
			val = xchg(&sk->sk_err_soft, 0);
		break;

	default:
		return -ENOPROTOOPT;
	}

	if (len > sizeof(int))
		len = sizeof(int);
	if (copy_to_user(optval, &val, len))
		return -EFAULT;

	return 0;
}

/*
 *	Set a socket option. Because we don't know the option lengths we have
 *	to pass the user mode parameter for the protocols to sort out.
 */
SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname,
		char __user *, optval, int, optlen)
{
	struct lego_socket *sock;
	struct file *f = fdget(fd);

	if (!f)
		return -ENFILE;
	sock = (struct lego_socket *)f->private_data;

	if (level == SOL_SOCKET) {
		sock_setsockopt(sock, level, optname, optval, optlen);
	}
	else if (level == SOL_TCP) {
		tcp_setsockopt(sock, level, optname, optval, optlen);
	}

	return 0;
}

/*
 *	Get a socket option. Because we don't know the option lengths we have
 *	to pass a user mode parameter for the protocols to sort out.
 */
SYSCALL_DEFINE5(getsockopt, int, fd, int, level, int, optname,
		char __user *, optval, int __user *, optlen)
{
	struct lego_socket *sock;
	struct file *f = fdget(fd);

	if (!f)
		return -ENFILE;
	sock = (struct lego_socket *)f->private_data;

	if (level == SOL_SOCKET) {
		sock_getsockopt(sock, level, optname, optval, optlen);
	}
	else if (level == SOL_TCP) {
		tcp_getsockopt(sock, level, optname, optval, optlen);
	}

	return 0;
}

/*
 *	Get the local address ('name') of a socket object. Move the obtained
 *	name to user space.
 */

SYSCALL_DEFINE3(getsockname, int, fd, struct sockaddr __user *, usockaddr,
		int __user *, usockaddr_len)
{
	struct lego_socket *sock;
	struct file *f = fdget(fd);

	if (!f)
		return -ENFILE;
	sock = (struct lego_socket *)f->private_data;

	if (sock->status >= SOCK_CREATED) {
		if (copy_to_user(usockaddr_len, &sock->sockaddr, sock->addr_len))
			return -EFAULT;
		return 0;
	}
	return -EBADF;
}

/*
 *	Bind a name to a socket. Nothing much to do here since it's
 *	the protocol's responsibility to handle the local address.
 */
SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, addr, int, addr_len)
{
	struct sockaddr_in sockaddr;
	int port;
	u32 saddr;
	u8_t sa_family;
	struct lego_socket *sock;
	struct file *f = fdget(fd);

	pr_crit("%s: fd %d f %p\n", __func__, fd, f);
	if (!f)
		return -ENFILE;
	sock = (struct lego_socket *)f->private_data;

	memcpy(&sockaddr, addr, addr_len);
	//if (copy_from_user(&sockaddr, addr, addr_len))
		//return -EFAULT;

	sa_family = sockaddr.sin_family;
	port = sockaddr.sin_port;
	saddr = sockaddr.sin_addr.s_addr;

	if (saddr != htonl(INADDR_ANY)) {
		pr_crit("Not supporting sa family other than INADDR_ANY currently!\n");
		return -EFAULT;
	}
	sock_debug("binding port %d\n", port);

	memcpy(&sock->sockaddr, &sockaddr, addr_len);
	sock->addr_len = addr_len;
	sock->sa_family = sa_family;
	sock->local_port = port;
	sock->status = SOCK_BOUND;
	sock->peer_node_id = -1; /* -1 for INADDR_ANY */

	sock->local_internal_port = set_internal_port(MY_NODE_ID, port);

	sock_debug("bound fd %d sock %p to port %d fit internal port %d\n", 
			fd, sock, port, sock->local_internal_port);

	return 0;
}

/*
 *	Perform a listen. Basically, we allow the protocol to do anything
 *	necessary for a listen, and if that works, we mark the socket as
 *	ready for listening.
 */
SYSCALL_DEFINE2(listen, int, fd, int, backlog)
{
	struct lego_socket *sock;
	struct file *f = fdget(fd);
	int ret_size = 0, receive_size;
	int sender_id;
	struct lego_sock_conn *sock_conn;

	sock_debug("%s: fd %d f %p\n", __func__, fd, f);
	if (!f)
		return -ENFILE;
	sock = (struct lego_socket *)f->private_data;
	sock->type |= f->f_flags;

	/* has to bind first, then listen */
	if (sock->status != SOCK_BOUND) {
		return -EINVAL;
	}
	sock->status = SOCK_LISTEN;
	sock->max_num_conn = backlog;
	sock->curr_num_conn = 0;
	
	sock_conn = (struct lego_sock_conn *)kmalloc(sizeof(struct lego_sock_conn), GFP_KERNEL);
	BUG_ON(!sock_conn);

	receive_size = sizeof(struct lego_sock_conn);
	sock_debug("%s: listening on fd %d backlog %d port %d local_port %d internal port %d\n", 
			__func__, fd, backlog, sock->local_port, sock->local_port, sock->local_internal_port);

	while (sock->curr_num_conn < sock->max_num_conn) {
		sock_debug("%s: fd %d curr_num_conn %d max_num_conn %d\n",
				__func__, fd, sock->curr_num_conn, sock->max_num_conn);
		ret_size= ibapi_sock_receive_message(&sender_id, sock->local_internal_port, (void *)sock_conn, receive_size, 0, sock->type);
		if (ret_size > 0)
			sock->curr_num_conn++;
		sock_debug("%s: retsize %d socktype %x\n", __func__, ret_size, sock->type);
		/* nonblocking socket, return immediately */
		if (ret_size == 0 && (sock->type & O_NONBLOCK)) {
			sock_debug("%s nonblocking socket, no incoming connections now.\n", __func__);
			break;
		}
		if (ret_size != sizeof(struct lego_sock_conn)) {
			pr_crit("BUG: [%s] received wrong sock data, smaller than sock header %d\n", __func__, ret_size);
		}
		if (sock_conn->op_code != SOCK_BUILD_CONN) { /* peer_fit_node_id field reused as OP code when sending */
			sock_debug("Error: got message to port %d from node %d other than connection request\n",
					sock->local_port, sender_id);
			return -EINVAL;
		}

		/* we now assume only one thread calling socket listen, so no need to lock the list */
		list_add(&sock_conn->list, &sock->recvd_conn_list.list);

		schedule();
	}

	return 0;
}

/*
 *	Attempt to connect to a socket with the server address.  The address
 *	is in user space so we verify it is OK and move it to kernel space.
 */
SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr,
		int, addrlen)
{
	struct sockaddr_in sockaddr;
	u32 saddr;
	int node_id;
	struct lego_sock_conn *sock_conn;
	struct lego_socket *sock;
	struct file *f = fdget(fd);
	int ret;
	struct sock_conn_handshake_metadata handshake_header;
	int sender_id;

	sock_debug("%s: fd %d f %p\n", __func__, fd, f);
	if (!f)
		return -ENFILE;
	sock_debug("%s: fd %d f %p private %p\n", __func__, fd, f, f->private_data);

	sock = (struct lego_socket *)f->private_data;
	if (!sock)
		return -ENFILE;
	sock->type |= f->f_flags;

	memcpy(&sockaddr, uservaddr, addrlen);
	//if (copy_from_user(&sockaddr, uservaddr, addrlen))
		//return -EFAULT;

	saddr = sockaddr.sin_addr.s_addr;
	/* node_id -1 means not bound to a specific conn */
	node_id = get_FIT_node_id_from_saddr(saddr);

	sock_debug("%s: connecting to node %d port %d\n", __func__, node_id, sockaddr.sin_port);
	memcpy(&sock->peer_sockaddr, &sockaddr, addrlen);
	sock->peer_addr_len = addrlen;
	sock->peer_node_id = node_id;
	sock->local_port = get_and_insert_new_local_port(node_id);
	sock->local_internal_port = get_internal_port(node_id, sock->local_port);

	sock_conn = (struct lego_sock_conn *)kmalloc(sizeof(struct lego_sock_conn), GFP_KERNEL);
	sock_conn->op_code = SOCK_BUILD_CONN;
	sock_conn->fit_node_id = MY_NODE_ID;
	sock_conn->sockaddr.sin_port = sock->local_port;
	sock_conn->sockaddr.sin_addr.s_addr = get_saddr_from_fit_node_id(MY_NODE_ID);
	sock_conn->sockaddr.sin_family = sock->sa_family;
	sock_conn->sockaddr_len = addrlen;
	sock_conn->internal_port = get_internal_port(node_id, sock->local_port);
	sock_debug("connect assigned internal local port %d fit port %d\n", 
			sock->local_port, sock_conn->internal_port);

	sock_debug("%s: dest node %d port %d\n", __func__, node_id, sock->peer_internal_port);
	/* 
	 * valid connection, 
	 * send special notice to target node
	 */
	ret = ibapi_sock_send_message(node_id, sockaddr.sin_port, 0, sock_conn, sizeof(struct lego_sock_conn), 30, 0);
	if (ret == 0) {
		sock->status = SOCK_CONNECT_REQUESTED;
		sock_debug("%s: sock connect requested\n", __func__);
		/*
		 * waiting for peer to accept the connection request
		 */
		ret = ibapi_sock_receive_message(&sender_id, sock->local_internal_port, 
				(void *)&handshake_header, sizeof(struct sock_conn_handshake_metadata), 0, 0);
		if (sender_id == node_id && ret > 0 && handshake_header.status == SOCK_CONNECT_ACCEPTED) {
			sock->peer_internal_port = handshake_header.peer_port;
			sock_debug("%s: sock connect accepted peer port %d\n", __func__, sock->peer_internal_port);
			/*
			 * send ack to peer
			 * finishing 3-way handshake
			 */
			handshake_header.status = SOCK_CONNECT_ACKED;
			handshake_header.peer_port = sock->local_internal_port;
			ret = ibapi_sock_send_message(node_id, sock->peer_internal_port, 1, 
					&handshake_header, sizeof(struct sock_conn_handshake_metadata), 30, 0);
			if (ret == 0) {
				sock->status = SOCK_CONNECTED;
				sock_debug("%s: sock connected to node %d port %d\n", 
						__func__, sock->peer_node_id, sock->peer_internal_port);
			}
		}
	}

	return ret;
}

/*
 *	For accept, we attempt to create a new socket, set up the link
 *	with the client, wake up the client, then return the new
 *	connected fd. We collect the address of the connector in kernel
 *	space and move it to user at the very end. This is unclean because
 *	we open the socket then return an error.
 */
SYSCALL_DEFINE4(accept4, int, fd, struct sockaddr __user *, upeer_sockaddr,
		int __user *, upeer_addrlen, int, flags)
{
	int new_fd, ret;
	struct lego_socket *sock, *new_sock;
	struct file *f = fdget(fd);
	struct file *new_f;
	struct lego_sock_conn *header;
	struct sock_conn_handshake_metadata handshake_header;
	int sender_id;
	int ret_size = 0, receive_size;
	struct lego_sock_conn *sock_conn;

	sock_debug("%s: fd %d f %p\n", __func__, fd, f);
	if (!f)
		return -ENFILE;

	/* do not support BLOCK now */
	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;

	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	sock = (struct lego_socket *)f->private_data;
	if (!sock)
		return -ENFILE;
	sock->type |= f->f_flags;

	sock_debug("%s: sock type %x curr_num_conn %d\n", __func__, sock->type, sock->curr_num_conn);
	/* nonblocking socket, when we get here, we need another ib receive */
	if (sock->type & O_NONBLOCK && sock->curr_num_conn == 0) {

		sock_conn = (struct lego_sock_conn *)kmalloc(sizeof(struct lego_sock_conn), GFP_KERNEL);
		BUG_ON(!sock_conn);
		receive_size = sizeof(struct lego_sock_conn);

		/* need a blocking receive when we get here */
		ret_size= ibapi_sock_receive_message(&sender_id, sock->local_internal_port, (void *)sock_conn, receive_size, 0, 1);
		if (ret_size > 0)
			sock->curr_num_conn++;

		sock_debug("%s: retsize %d socktype %x\n", __func__, ret_size, sock->type);
		if (ret_size != sizeof(struct lego_sock_conn)) {
			pr_crit("BUG: [%s] received wrong sock data, smaller than sock header %d\n", __func__, ret_size);
		}
		if (sock_conn->op_code != SOCK_BUILD_CONN) { /* peer_fit_node_id field reused as OP code when sending */
			sock_debug("Error: got message to port %d from node %d other than connection request\n",
					sock->local_port, sender_id);
			return -EINVAL;
		}
		/* we now assume only one thread calling socket listen, so no need to lock the list */
		list_add(&sock_conn->list, &sock->recvd_conn_list.list);
	}

	new_sock = (struct lego_socket *)kzalloc(sizeof(struct lego_socket), GFP_KERNEL);
	BUG_ON(!new_sock);
	new_fd = sys_open("sock/accept", O_RDWR | O_CREAT, 0);
	new_f = fdget(new_fd);
	if (!f || !new_f)
		return -ENFILE;
	sock_debug("%s: new_fd %d new_f %p\n", __func__, new_fd, new_f);
	new_f->private_data = (void *)new_sock;

	new_sock->fd = new_fd;
	memcpy(&new_sock->sockaddr, &sock->sockaddr, sock->addr_len);
	new_sock->addr_len = sock->addr_len;
	new_sock->sa_family = sock->sa_family;
	new_sock->type = sock->type;
	new_sock->file = new_f;

	if (list_empty(&sock->recvd_conn_list.list)) {
		sock_debug("%s: no incoming connection\n", __func__);
		return -EINVAL;
	}
	
	header = list_first_entry(&sock->recvd_conn_list.list, struct lego_sock_conn, list);
	list_del(&header->list);

	memcpy(&new_sock->peer_sockaddr, &header->sockaddr, header->sockaddr_len);
	new_sock->peer_addr_len = header->sockaddr_len;
	new_sock->peer_internal_port = header->internal_port;
	new_sock->peer_node_id = header->fit_node_id;
	new_sock->local_port = get_and_insert_new_local_port(new_sock->peer_node_id);
	new_sock->local_internal_port = get_internal_port(new_sock->peer_node_id, new_sock->local_port);
	sock_debug("%s: got connection request fro mnode %d, assigned local port %d internalport %d\n",
			__func__, new_sock->peer_node_id, new_sock->local_port, new_sock->local_internal_port);
	
	if (upeer_addrlen != NULL) {
		ret = copy_to_user(upeer_sockaddr, &header->sockaddr, header->sockaddr_len);
		ret = copy_to_user(upeer_addrlen, &header->sockaddr_len, sizeof(int));
	}

	spin_lock(&global_sock_list_lock);
	list_add_tail(&new_sock->list, &global_socket_list);
	spin_unlock(&global_sock_list_lock);

	new_sock->status = SOCK_CONNECT_ACCEPTED;

	/*
	 * replies to peer on getting the connection request
	 * and accepted the request
	 */
	new_sock->status = SOCK_CONNECT_ACCEPTED;
	handshake_header.status = SOCK_CONNECT_ACCEPTED;
	handshake_header.peer_port = new_sock->local_internal_port; 
	ret = ibapi_sock_send_message(header->fit_node_id, new_sock->peer_internal_port, 1, 
			&handshake_header, sizeof(struct sock_conn_handshake_metadata), 30, 0);
	if (ret) {
		pr_crit("%s: error sending accept signal back to %d:%d\n", 
				__func__, header->fit_node_id, header->sockaddr.sin_port);
		return -EINVAL;
	}

	ret = ibapi_sock_receive_message(&sender_id, new_sock->local_internal_port, 
			(void *)&handshake_header, sizeof(struct sock_conn_handshake_metadata), 0, 0);
	if (ret > 0 && handshake_header.status == SOCK_CONNECT_ACKED) {
		sock_debug("%s succesfully connected to node %d port %d!\n", 
				__func__, new_sock->peer_node_id, new_sock->peer_internal_port);
		new_sock->status = SOCK_CONNECTED;
	}

	return new_fd;
}

SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr,
		int __user *, upeer_addrlen)
{
	return sys_accept4(fd, upeer_sockaddr, upeer_addrlen, 0);
}

/*
 * return:
 * 0 succeed in sending all data
 */
int socket_send_data(struct lego_socket *sock, void __user *buff, size_t len)
{
	int ret;

	if (len <= 0) {
		pr_crit("%s: sending size wrong %zu\n", __func__, len);
		return -1;
	}
	if (len > MAX_SOCK_SEND_SIZE) {
		pr_crit("%s: sending too big %zu. currently only support sending up to %dB\n",
				__func__, len, MAX_SOCK_SEND_SIZE);
		return -1;
	}

	if (!sock) {
		pr_crit("%s: wrong null socket\n", __func__);
		return -1;
	}

	ret = ibapi_sock_send_message(sock->peer_node_id, sock->peer_internal_port, 1, buff, len, 30, 1);

	return ret;
}

/*
 *	Send a datagram to a given address. We move the address into kernel
 *	space and check the user space data area is readable before invoking
 *	the protocol.
 */
SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
		unsigned int, flags, struct sockaddr __user *, addr,
		int, addr_len)
{
	struct file *f = fdget(fd);

	if (!f)
		return -ENFILE;

	if (addr_len > 0 && addr != NULL) {
		pr_crit("%s: not supporting non-connection-based socket yet!\n", __func__);
		return -1;
	}

	return socket_send_data((struct lego_socket *)f->private_data, buff, len);
}

/*
 *	Send a datagram down a socket.
 */
SYSCALL_DEFINE4(send, int, fd, void __user *, buff, size_t, len,
		unsigned int, flags)
{
	return sys_sendto(fd, buff, len, flags, NULL, 0);
}

/*
 * send iovec msg
 * return: total size sent successfully
 */
SYSCALL_DEFINE3(sendmsg, int, fd, struct user_msghdr __user *, msg, 
		unsigned int, flags)
{
	struct file *f;
	ssize_t err;
	int i;
	struct iovec *iov;
	int total_sent_size = 0;

	if (flags & MSG_CMSG_COMPAT)
		return -EINVAL;
	f = fdget(fd);
	if (!f)
		return -ENFILE;

	if (msg->msg_namelen < 0)
		return -EINVAL;

	if (msg->msg_namelen > 0) 
		pr_crit("WARNING: %s doesn't support msg name now\n", __func__);

	err = -ENOBUFS;

	if (msg->msg_controllen) {
		pr_crit("WARNING: %s doesn't support msgctl now\n", __func__);
	}

//	if (sock->file->f_flags & O_NONBLOCK)
//		msg_sys->msg_flags |= MSG_DONTWAIT;

	iov = (struct iovec *)kmalloc(sizeof(struct iovec) * msg->msg_iovlen, GFP_KERNEL);
	memcpy(iov, msg->msg_iov, sizeof(struct iovec) * msg->msg_iovlen);
	// XXX copy_from_user(iov, msg->msg_iov, sizeof(struct iovec) * msg->msg_iovlen);

	for (i = 0; i < msg->msg_iovlen; i++) {
		err = socket_send_data((struct lego_socket *)f->private_data, iov[i].iov_base, iov[i].iov_len);
		if (err == 0) {
			total_sent_size += iov[i].iov_len;
		}
	}

	kfree(iov);
	return total_sent_size;
}

int socket_receive_data(struct lego_socket *sock, void __user *ubuf, size_t size, int sock_type)
{
	int ret_size;
	int sender_id;

	if (!sock) {
		pr_crit("%s: wrong null socket\n", __func__);
		return -1;
	}

	if (sock->status != SOCK_CONNECTED) {
		pr_crit("%s: socket not connected yet status %d\n", __func__, sock->status);
		return -1;
	}

	ret_size = ibapi_sock_receive_message(&sender_id, sock->local_internal_port, ubuf, size, 1, sock_type);
			
	return ret_size;
}

/*
 *	Receive a frame from the socket and optionally record the address of the
 *	sender. We verify the buffers are writable and if needed move the
 *	sender address from kernel to user space.
 */
SYSCALL_DEFINE6(recvfrom, int, fd, void __user *, ubuf, size_t, size,
		unsigned int, flags, struct sockaddr __user *, addr,
		int __user *, uaddr_len)
{
	struct file *f;
	struct lego_socket *sock;

	f = fdget(fd);
	if (!f)
		return -ENFILE;

	if (uaddr_len != NULL && addr != NULL) {
		pr_crit("%s: not supporting non-connection-based socket yet!\n", __func__);
		return -1;
	}

	sock = (struct lego_socket *)f->private_data;
	
	return socket_receive_data(sock, ubuf, size, sock->type & O_NONBLOCK);
}

/*
 *	Receive a datagram down a socket.
 */
SYSCALL_DEFINE4(recv, int, fd, void __user *, buff, size_t, len,
		unsigned int, flags)
{
	return sys_recvfrom(fd, buff, len, flags, NULL, 0);
}

SYSCALL_DEFINE3(recvmsg, int, fd, struct user_msghdr __user *, msg, 
		unsigned int, flags)
{
	struct file *f;
	ssize_t err;
	int i;
	struct iovec *iov;
	int total_received_size = 0;
	char *buf;
	int remain_size, ret;
	struct lego_socket *sock;

	if (flags & MSG_CMSG_COMPAT)
		return -EINVAL;
	f = fdget(fd);
	if (!f)
		return -ENFILE;

	if (msg->msg_namelen < 0)
		return -EINVAL;

	if (msg->msg_namelen > 0) 
		pr_crit("WARNING: %s doesn't support msg name now\n", __func__);

	err = -ENOBUFS;

	if (msg->msg_controllen) {
		pr_crit("WARNING: %s doesn't support msgctl now\n", __func__);
	}

	sock = (struct lego_socket *)f->private_data;

	iov = (struct iovec *)kmalloc(sizeof(struct iovec) * msg->msg_iovlen, GFP_KERNEL);
	memcpy(iov, msg->msg_iov, sizeof(struct iovec) * msg->msg_iovlen);
	// XXX copy_from_user(iov, msg->msg_iov, sizeof(struct iovec) * msg->msg_iovlen);

	for (i = 0; i < msg->msg_iovlen; i++) {
		remain_size = iov[i].iov_len;
		buf = (char *)iov[i].iov_base;

		while (remain_size > 0) {
			ret = socket_receive_data(sock, buf, remain_size, sock->type);
			if (ret <= 0)
				goto out_freeiov;
			total_received_size += ret;
			remain_size -= ret;
			buf += ret;
			sock_debug("%s: received size %d remain_size %d iov %d\n",
					__func__, ret, remain_size, i);
		}
	}

out_freeiov:
	kfree(iov);

	sock_debug("%s: exit received size %d\n", __func__, total_received_size);
	return total_received_size;
}

/*
 *	Shutdown a socket.
 */
SYSCALL_DEFINE2(shutdown, int, fd, int, how)
{
	struct file *f;
	struct lego_socket *sock;
	int ret;

	f = fdget(fd);
	if (!f)
		return -ENFILE;

	sock = (struct lego_socket *)f->private_data;

//XXX TODO
	return ret;
}

static int sock_open(struct file *f)
{
	sock_debug("%s\n", __func__);
	return 0;
}

static ssize_t sock_read(struct file *f, char __user *buf,
			size_t count, loff_t *off)
{
	struct lego_socket *sock;

	sock_debug("%s\n", __func__);

	sock = (struct lego_socket *)f->private_data;
	return socket_receive_data(sock, buf, count, sock->type & O_NONBLOCK);
}

static ssize_t sock_write(struct file *f, const char __user *buf,
			size_t count, loff_t *off)
{
	sock_debug("%s\n", __func__);
	return socket_send_data((struct lego_socket *)f->private_data, (char __user *)buf, count);
}

/* currently only used in epoll */
static unsigned int sock_poll(struct file *file)
{
	struct lego_socket *sock;

	sock = file->private_data;

	return sock->ready_state;
}

/* File callbacks that implement the socket fd behaviour */
static const struct file_operations socket_fops = {
	.open		= sock_open,
	.read		= sock_read,
	.write		= sock_write,
	.poll		= sock_poll,
};

/* 
 * Find file using target node ID and FIT internal port number
 * For INADDR_ANY, target_node is not used for any matching
 * WARN: still need to take care of socket reuse addr and port
 */
struct lego_socket *find_socket_from_node_port(int target_node, int port)
{
	struct lego_socket *sock;

	//sock_debug("%s finding target_node %d port %d\n", __func__, target_node, port);
	spin_lock(&global_sock_list_lock);
	list_for_each_entry(sock, &global_socket_list, list) {
		if (sock->local_internal_port == port) {
			if (sock->peer_node_id == -1 || sock->peer_node_id == target_node) {
					break;
			}
		}
	}
	spin_unlock(&global_sock_list_lock);

	//sock_debug("%s: node %d port %d sock %p\n", __func__, target_node, port, sock);

	return sock;
}

int sock_set_read_ready(int target_node, int port, int size)
{
	struct lego_socket *sock;

	sock = find_socket_from_node_port(target_node, port);
	if (!sock) {
		printk(KERN_CRIT "Error: couldn't find socket for node %d port %d\n",
				target_node, port);
		return -EINVAL;
	}

	sock->file->ready_size += size;
	sock->ready_state |= POLLIN;
	sock->file->ready_state |= POLLIN;

	sock_debug("%s: node %d port %d sock %p file %p read ready size %d\n", 
			__func__, target_node, port, sock, sock->file, sock->file->ready_size);

	return 0;
}

int sock_unset_read_ready(int target_node, int port, int size)
{
	struct lego_socket *sock;

	sock = find_socket_from_node_port(target_node, port);
	if (!sock) {
		printk(KERN_CRIT "Error: couldn't find socket for node %d port %d\n",
				target_node, port);
		return -EINVAL;
	}

	sock->file->ready_size -= size;
	if (sock->file->ready_size <= 0) {
		sock->ready_state &= !POLLIN;
		sock->file->ready_state &= !POLLIN;
	}

	sock_debug("%s: node %d port %d sock %p file %p read not ready readysize %d\n", 
			__func__, target_node, port, sock, sock->file, sock->file->ready_size);

	return 0;
}

int sock_set_write_ready(int target_node, int port)
{
	struct lego_socket *sock;

	sock = find_socket_from_node_port(target_node, port);
	if (!sock) {
		printk(KERN_CRIT "Error: couldn't find socket file for node %d port %d\n",
				target_node, port);
		return -EINVAL;
	}

	sock->ready_state |= POLLOUT;
	sock->file->ready_state |= POLLOUT;

	sock_debug("%s: node %d port %d sock %p write ready\n", __func__, target_node, port, sock);

	return 0;
}

#ifdef CONFIG_EPOLL
int sock_epoll_callback(int target_node, int port)
{
	struct lego_socket *sock;
	struct file *f;

	sock = find_socket_from_node_port(target_node, port);
	if (!sock) {
		printk(KERN_CRIT "Error: couldn't find socket file for node %d port %d\n",
				target_node, port);
		return -EINVAL;
	}

	f = sock->file;

	sock_debug("%s: node %d port %d file %p sock %p ready state %x\n", 
			__func__, target_node, port, f, sock, sock->ready_state);

	lego_epoll_callback(f, (void *)sock->ready_state);

	return 0;
}
#endif

int sock_poll_callback(int target_node, int port)
{
	struct lego_socket *sock;
	struct file *f;

	sock = find_socket_from_node_port(target_node, port);
	if (!sock) {
		printk(KERN_CRIT "Error: couldn't find socket file for node %d port %d\n",
				target_node, port);
		return -EINVAL;
	}

	f = sock->file;

	sock_debug("%s: node %d port %d file %p sock %p ready state %x\n", 
			__func__, target_node, port, f, sock, sock->ready_state);

	lego_poll_callback(f);

	return 0;
}

/*
 * Callback for syscall open()
 * Used to install socket-specific file operations
 */
int socket_file_open(struct file *filp)
{
	filp->f_op = &socket_fops;
	return 0;
}

/* testing socket server */
#define SERV_PORT 3000
#define MAXEVENTS 100

typedef union epoll_data {
	void    *ptr;
	int      fd;
	uint32_t u32;
	uint64_t u64;
} epoll_data_t;

struct user_epoll_event {
	uint32_t     events;    /* Epoll events */
	epoll_data_t data;      /* User data variable */
};

#ifdef CONFIG_SOCKET_SERVER

static void test_socket_server(void)
{
	int listenfd, connfd;
	struct sockaddr_in cliaddr, servaddr;
	int clilen, n, i;
	char buf[4096];
	struct user_msghdr msg;
	struct iovec iov[3];
	char buf1[16];
	char buf2[8];
	char buf3[32];
	int efd, s;
	struct user_epoll_event event;  
	struct user_epoll_event *events;  
	int count;

	/* Buffer where events are returned */  
	events = kzalloc(MAXEVENTS * sizeof(struct epoll_event), GFP_KERNEL);
  
	sock_debug("%s\n", __func__);

	listenfd = sys_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	sock_debug("%s got fd %d\n", __func__, listenfd);

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(SERV_PORT);

	sys_bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr));

	sys_listen(listenfd, 1);

	sock_debug("socket server listening on port %d\n", SERV_PORT);

	efd = sys_epoll_create1(0); 
	BUG_ON(efd <= 0);

	event.data.fd = listenfd; 
	event.events = POLLIN | EPOLLET;
	s = sys_epoll_ctl(efd, EPOLL_CTL_ADD, listenfd, &event);
	BUG_ON(s);

	while (1) {
		n = sys_epoll_wait(efd, events, MAXEVENTS, -1); /* -1 never time out */
		for (i = 0; i < n; i++) {
			if ((events[i].events & POLLERR) ||  
					(events[i].events & POLLHUP) ||  
					(!(events[i].events & POLLIN)))  
			{  
				/* An error has occured on this fd, or the socket is not 
				   ready for reading (why were we notified then?) */  
				printk(KERN_CRIT "epoll error %x\n", events[i].events);  
				continue;  
			}
			else if (events[i].data.fd == listenfd) {
				sock_debug("received on listening conn %d\n", listenfd);
				while (1) {
					connfd = sys_accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);
					if (connfd > 0) {
						sock_debug("received connection request connected on fd %d\n", connfd);
					}

					event.data.fd = connfd;
					event.events = POLLIN | EPOLLET;  
					s = sys_epoll_ctl(efd, EPOLL_CTL_ADD, connfd, &event);  

					break;
				}
			}
			else {
				sock_debug("received on conn %d\n", events[i].data.fd);
				count = sys_read(events[i].data.fd, buf, 4096);  
				if (count > 0) {			
					sock_debug("received buffer size %d %c\n", count, buf[0]);
					buf[0] = 'b';
					sys_send(events[i].data.fd, buf, 4096, 0);
				}
				
				struct pollfd fds[2];
				fds[0].fd = events[i].data.fd;
				fds[0].events = POLLIN;
				n = sys_poll(fds, 1, 60000);
				if (n > 0) {
					sock_debug("poll got %d events\n", n);
					count = sys_read(fds[0].fd, buf, 4096);
					sock_debug("received poll buffer size %d %c\n", count, buf[0]);
				}
			}
		}
	}


/*
	n = sys_recv(connfd, buf, 4096, 0);
	if (n > 0) {
		sock_debug("received buffer size %d %c\n", n, buf[0]);
		buf[0] = 'b';
		sys_send(connfd, buf, 4096, 0);
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 3;
	iov[0].iov_base = buf1;
	iov[0].iov_len = 16;
	iov[1].iov_base = buf2;
	iov[1].iov_len = 8;
	iov[2].iov_base = buf3;
	iov[2].iov_len = 32;

	for (i = 0; i < CONFIG_FIT_INITIAL_SLEEP_TIMEOUT * 1000; i++) 
		udelay(1000);
	n = sys_recvmsg(connfd, &msg, 0);
	sock_debug("received %d total data, buf1 %s buf2 %s buf3 %s\n",
			n, buf1, buf2, buf3);
*/
}
#endif

/* testing socket client */
#ifdef CONFIG_SOCKET_CLIENT
static void test_socket_client(void)
{
	int sockfd;
	struct sockaddr_in servaddr;
	int i, n;
	int ret;
	char buf[4096];
	struct user_msghdr msg;
	struct iovec iov[2];
	char buf1[16] = "abcdefghijklmnop";
	char buf2[16] = "1234567890uvwxyz";
	struct user_epoll_event event;  
	struct user_epoll_event *events;  
	int efd, s;

	/* Buffer where events are returned */  
	events = kzalloc(MAXEVENTS * sizeof(struct epoll_event), GFP_KERNEL);

	efd = sys_epoll_create1(0); 
	BUG_ON(efd <= 0);

	for (i = 0; i < CONFIG_FIT_INITIAL_SLEEP_TIMEOUT * 1000; i++) {
		udelay(1000);
	}
	if ((sockfd = sys_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0) {
		printk(KERN_CRIT "error in creating socket\n");
		return;
	}
	sock_debug("%s: fd %d\n", __func__, sockfd);

	event.data.fd = sockfd; 
	event.events = POLLIN | EPOLLET;
	s = sys_epoll_ctl(efd, EPOLL_CTL_ADD, sockfd, &event);
	BUG_ON(s);

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = 0x14732e80; //0x91732e80; //inet_addr("128.46.115.145");
	servaddr.sin_port = htons(SERV_PORT);

	if (sys_connect(sockfd, (struct sockaddr *) &servaddr, sizeof (servaddr)) < 0) {
		printk(KERN_CRIT "error connecting to server");
	}

	buf[0] = 'a';
	ret = sys_send(sockfd, buf, 4096, 0);
	n = sys_epoll_wait(efd, events, MAXEVENTS, -1); /* -1 never time out */
	sock_debug("received on conn %d\n", events[i].data.fd);
	ret = sys_recv(sockfd, buf, 4096, 0);
	sock_debug("received buffer size %d %c\n", ret, buf[0]);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	iov[0].iov_base = buf1;
	iov[0].iov_len = 16;
	iov[1].iov_base = buf2;
	iov[1].iov_len = 16;
	buf1[0] = 'z';

	n = sys_sendmsg(sockfd, &msg, 0);
	sock_debug("sent %d total data, buf1 %s buf2 %s\n",
			n, buf1, buf2);
}
#endif

void test_socket(void)
{
#ifdef CONFIG_SOCKET_SERVER
	test_socket_server();
#endif
#ifdef CONFIG_SOCKET_CLIENT
	test_socket_client();
#endif
}

void init_socket(void)
{
	int i;

	init_sock_ips();
	atomic_set(&global_flow_id, 0);
	INIT_LIST_HEAD(&global_socket_list);
	spin_lock_init(&global_sock_list_lock);
	global_buffer_for_no_sock = (char *)kmalloc(MAX_BUF_SIZE_FOR_NO_SOCK, GFP_KERNEL);
	global_buffer_for_no_sock_size = 0;

	for (i = 0; i < MAX_NODE; i++) {
		hash_init(port_hash[i]);
		spin_lock_init(&port_hash_lock[i]);
	}
	bitmap_clear(sock_local_port_bitmap, 0, MAX_KERNEL_SOCK_PORTS);
	bitmap_clear(fit_local_port_bitmap, 0, SOCK_MAX_LISTEN_PORTS);
}
