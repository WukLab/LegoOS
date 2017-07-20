/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file records SYSCALLs that are ONLY available
 * at processor-component. We just define a simple prototypes
 * here and panic in case someone calls.
 */

#include <lego/kernel.h>
#include <lego/syscalls.h>

SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	BUG();
}

SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	BUG();
}

SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
	BUG();
}

SYSCALL_DEFINE1(close, unsigned int, fd)
{
	BUG();
}

SYSCALL_DEFINE3(execve,
		const char __user*, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp)
{
	BUG();
}

SYSCALL_DEFINE1(brk, unsigned long, brk)
{
	BUG();
}

SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags,
		unsigned long, fd, unsigned long, off)
{
	BUG();
}

SYSCALL_DEFINE2(munmap, unsigned long, addr, size_t, len)
{
	BUG();
}

SYSCALL_DEFINE3(msync, unsigned long, start, size_t, len, int, flags)
{
	BUG();
}
