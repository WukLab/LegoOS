/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file defines all socket syscall hooks:
 * 	socket
 * 	sendto
 * 	recvfrom
 * 	setsockopt
 * 	getsockopt
 */

#include <lego/syscalls.h>
#include <lego/socket.h>
#include <lego/atomic.h>
#include <processor/processor.h>

atomic_t global_sockfd;

SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
	return atomic_add_return(1, &global_sockfd);
}

/*
 *	Set a socket option. Because we don't know the option lengths we have
 *	to pass the user mode parameter for the protocols to sort out.
 */
SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname,
		char __user *, optval, int, optlen)
{
	return 0;
}

/*
 *	Get a socket option. Because we don't know the option lengths we have
 *	to pass a user mode parameter for the protocols to sort out.
 */
SYSCALL_DEFINE5(getsockopt, int, fd, int, level, int, optname,
		char __user *, optval, int __user *, optlen)
{
	return 0;
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
	struct sockaddr_in sockaddr;
	int port;
	u32_t saddr;
	char *kbuff = (char *)kmalloc(len, GFP_KERNEL);
	int reply;
	int ret;

	if (copy_from_user(&sockaddr, addr, addr_len))
		return -EFAULT;

	port = sockaddr.sin_port;
	saddr = sockaddr.sin_addr.s_addr;
	if (copy_from_user(kbuff, buff, len))
		return -EFAULT;

	ret = ibapi_send_reply_imm(port, kbuff, len, &reply, sizeof(int));

	return ret;
}

/*
 *	Receive a frame from the socket and optionally record the address of the
 *	sender. We verify the buffers are writable and if needed move the
 *	sender address from kernel to user space.
 */
SYSCALL_DEFINE6(recvfrom, int, fd, void __user *, ubuf, size_t, size,
		unsigned int, flags, struct sockaddr __user *, addr,
		int __user *, addr_len)
{

	struct sockaddr sockaddr;
	if (copy_from_user(&sockaddr, addr, addr_len))
		return -EFAULT;

	ibapi_receive_message_only(port, input_addr, max_len);
}
