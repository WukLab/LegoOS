/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file describes all file-related syscalls
 */

#include <lego/files.h>
#include <lego/syscalls.h>
#include <lego/comp_processor.h>

SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	debug_syscall_print();
	return 0;
}

SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	debug_syscall_print();
	return 0;
}

SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
	debug_syscall_print();
	return 0;
}

SYSCALL_DEFINE1(close, unsigned int, fd)
{
	debug_syscall_print();
	return 0;
}

static ssize_t do_readv(unsigned long fd, const struct iovec __user *vec,
			unsigned long vlen, int flags)
{
	debug_syscall_print();
	return -EFAULT;
}

static ssize_t do_writev(unsigned long fd, const struct iovec __user *vec,
			 unsigned long vlen, int flags)
{
	debug_syscall_print();
	return -EFAULT;
}
SYSCALL_DEFINE3(readv, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	return do_readv(fd, vec, vlen, 0);
}

SYSCALL_DEFINE3(writev, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	return do_writev(fd, vec, vlen, 0);
}
