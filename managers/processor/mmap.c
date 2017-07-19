/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/syscalls.h>
#include <lego/comp_processor.h>

SYSCALL_DEFINE1(brk, unsigned long, brk)
{
	struct p2m_brk_struct payload;
	unsigned long ret_brk;
	int ret;

	payload.pid = current->pid;
	payload.brk = brk;

	ret = net_send_reply_timeout(DEF_MEM_HOMENODE, P2M_BRK,
			&payload, sizeof(payload), &ret_brk, sizeof(ret_brk),
			false, DEF_NET_TIMEOUT);

	if (likely(ret == sizeof(ret_brk))) {
		if (WARN_ON(ret == RET_ESRCH || ret == RET_EINTR))
			return -EINTR;
		return ret_brk;
	}
	return -EIO;
}

SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags,
		unsigned long, fd, unsigned long, off)
{
	struct p2m_mmap_struct payload;
	unsigned long ret_addr;
	int ret;

	if (offset_in_page(off))
		return -EINVAL;
	if (!len)
		return -EINVAL;
	len = PAGE_ALIGN(len);
	if (!len)
		return -ENOMEM;
	/* overflowed? */
	if ((off + len) < off)
		return -EOVERFLOW;

	payload.pid = current->pid;
	payload.addr = addr;
	payload.len = len;
	payload.prot = prot;
	payload.flags = flags;
	payload.fd = fd;
	payload.off = off;

	ret = net_send_reply_timeout(DEF_MEM_HOMENODE, P2M_MMAP,
			&payload, sizeof(payload), &ret_addr, sizeof(ret_addr),
			false, DEF_NET_TIMEOUT);

	if (likely(ret == sizeof(ret_addr))) {
		return ret_addr;
	}
	return -EIO;
}

SYSCALL_DEFINE2(munmap, unsigned long, addr, size_t, len)
{
	struct p2m_munmap_struct payload;
	int ret, retbuf;

	if (offset_in_page(addr) || addr > TASK_SIZE || len > TASK_SIZE - addr)
		return -EINVAL;
	if (!len)
		return -EINVAL;
	len = PAGE_ALIGN(len);
	if (!len)
		return -EINVAL;

	payload.pid = current->pid;
	payload.addr = addr;
	payload.len = len;

	ret = net_send_reply_timeout(DEF_MEM_HOMENODE, P2M_MUNMAP,
			&payload, sizeof(payload), &retbuf, sizeof(retbuf),
			false, DEF_NET_TIMEOUT);

	if (likely(ret == sizeof(retbuf)))
		return retbuf;
	return -EIO;
}
