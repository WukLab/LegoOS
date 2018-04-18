
/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/smp.h>
#include <lego/mmap.h>
#include <lego/ptrace.h>
#include <lego/strace.h>
#include <lego/sched.h>
#include <lego/syscalls.h>
#include <lego/waitpid.h>
#include <lego/files.h>
#include <lego/sched.h>
#include <processor/fs.h>
#include <generated/asm-offsets.h>
#include <generated/unistd_64.h>

#include "internal.h"

static struct strace_flag sf_fcntl_flags[] = {
	SF(O_ACCMODE),
	SF(O_RDONLY),
	SF(O_WRONLY),
	SF(O_RDWR),
	SF(O_CREAT),
	SF(O_EXCL),
	SF(O_NOCTTY),
	SF(O_TRUNC),
	SF(O_APPEND),
	SF(O_NONBLOCK),
	SF(O_DSYNC),
	SF(FASYNC),
	SF(O_DIRECT),
	SF(O_LARGEFILE),
	SF(O_DIRECTORY),
	SF(O_NOFOLLOW),
	SF(O_NOATIME),
	SF(O_CLOEXEC),
	SF(O_NDELAY),
	SEND,
};

STRACE_DEFINE2(pipe2, int __user *, flides, int, flags)
{
	unsigned char buf_flags[128];

	memset(buf_flags, 0, 128);
	strace_printflags(sf_fcntl_flags, flags, buf_flags);

	sp("flides=%p, flags(%#x)=%s", flides, flags, buf_flags);
}

STRACE_DEFINE1(pipe, int __user *, flides)
{
	sp("flides=%p", flides);
}

STRACE_DEFINE1(dup, unsigned int, fildes)
{
	sp("fd=%u", fildes);
}

STRACE_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd)
{
	sp("oldfd=%u, newfd=%u", oldfd, newfd);
}
