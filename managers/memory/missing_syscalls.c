/*
 * Copyright (c) 2016-2020 Wuklab, Purdue University. All rights reserved.
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

#include <lego/stat.h>
#include <lego/files.h>
#include <lego/kernel.h>
#include <lego/syscalls.h>
#include <lego/getcpu.h>
#include <lego/waitpid.h>
#include <processor/pcache.h>

SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	BUG();
}

SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	BUG();
}

SYSCALL_DEFINE4(pread64, unsigned int, fd, char __user *, buf,
		size_t, count, loff_t, pos)
{
	BUG();
}

SYSCALL_DEFINE4(pwrite64, unsigned int, fd, const char __user *, buf,
		size_t, count, loff_t, pos)
{
	BUG();
}

SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
	BUG();
}

SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename,
		int, flags, umode_t, mode)
{
	BUG();
}

SYSCALL_DEFINE3(lseek, unsigned int, fd, off_t, offset, unsigned int, whence)
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

SYSCALL_DEFINE5(mremap, unsigned long, addr, unsigned long, old_len,
		unsigned long, new_len, unsigned long, flags,
		unsigned long, new_addr)
{
	BUG();
}

SYSCALL_DEFINE3(mprotect, unsigned long, start, size_t, len,
		unsigned long, prot)
{
	BUG();
}

SYSCALL_DEFINE3(msync, unsigned long, start, size_t, len, int, flags)
{
	BUG();
}

SYSCALL_DEFINE3(readv, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	BUG();
}

SYSCALL_DEFINE3(writev, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	BUG();
}

SYSCALL_DEFINE2(newstat, const char __user *, filename,
		struct stat __user *, statbuf)
{
	BUG();
}

SYSCALL_DEFINE2(newlstat, const char __user *, filename,
		struct stat __user *, statbuf)
{
	BUG();
}

SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)
{
	BUG();
}

SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
		struct stat __user *, statbuf, int, flag)
{
	BUG();
}

SYSCALL_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd)
{
	BUG();
}

SYSCALL_DEFINE1(dup, unsigned int, fildes)
{
	BUG();
}

SYSCALL_DEFINE3(fcntl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{
	BUG();
}

SYSCALL_DEFINE1(checkpoint_process, pid_t, pid)
{
	BUG();
}

SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{
	BUG();
}

SYSCALL_DEFINE1(pcache_stat, struct pcache_stat __user *, statbuf)
{
	BUG();
}

SYSCALL_DEFINE2(access, const char __user *, filename, int, mode)
{
	BUG();
}

SYSCALL_DEFINE5(waitid, int, which, pid_t, upid, struct siginfo __user *,
		infop, int, options, struct rusage __user *, ru)
{
	BUG();
}

SYSCALL_DEFINE0(sync)
{
	BUG();
}

SYSCALL_DEFINE2(truncate, const char __user *, path, long, length)
{
	BUG();
}

SYSCALL_DEFINE2(ftruncate, unsigned int, fd, unsigned long, length)
{
	BUG();
}


SYSCALL_DEFINE2(creat, const char  __user *, pathname, umode_t, mode)
{
	BUG();
}

SYSCALL_DEFINE1(unlink, const char __user *, pathname)
{
	BUG();
}

SYSCALL_DEFINE3(unlinkat, int, dfd, const char __user *, pathname, int, flag)
{
	BUG();
}

SYSCALL_DEFINE2(mkdir, const char __user *, pathname, umode_t, mode)
{
	BUG();
}

SYSCALL_DEFINE1(rmdir, const char __user *, pathname)
{
	BUG();
}

SYSCALL_DEFINE2(getcwd, char __user *, buf, unsigned long, size)
{
	BUG();
}

SYSCALL_DEFINE2(statfs, const char __user *, pathname, struct statfs __user *, buf)
{
	BUG();
}

SYSCALL_DEFINE3(getdents, unsigned int, fd,
		struct lego_dirent __user *, dirent, unsigned int, count)
{
	BUG();
}

SYSCALL_DEFINE3(readlink, const char __user *, path, char __user *, buf,
		int, bufsiz)
{
	BUG();
}

SYSCALL_DEFINE4(wait4, pid_t, upid, int __user *, stat_addr,
		int, options, struct rusage __user *, ru)
{
	BUG();
}

SYSCALL_DEFINE2(pipe2, int __user *, flides, int, flags)
{
	BUG();
}

SYSCALL_DEFINE1(pipe, int __user *, flides)
{
	BUG();
}

SYSCALL_DEFINE2(rename, const char __user *, oldname,
		const char __user *, newname)
{
	BUG();
}

SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
		unsigned long, arg4, unsigned long, arg5)
{
	BUG();
}

SYSCALL_DEFINE0(drop_page_cache)
{
	BUG();
}

SYSCALL_DEFINE1(fsync, unsigned int, fd)
{
	BUG();
}
