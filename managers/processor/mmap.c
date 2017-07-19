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

static long sys_mmap_pgoff(unsigned long addr, unsigned long len,
			   unsigned long prot, unsigned long flags,
			   unsigned long fd, unsigned long pgoff)
{
	return 0;			
}

SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags,
		unsigned long, fd, unsigned long, off)
{
	if (off & ~PAGE_MASK)
		return -EINVAL;

	return sys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);
}
