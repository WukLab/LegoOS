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

static struct strace_flag sf_mmap_prot[] = {
	SF(PROT_READ),
	SF(PROT_WRITE),
	SF(PROT_EXEC),
	SF(PROT_SEM),
	SF(PROT_NONE),
	SEND,
};

static struct strace_flag sf_mmap_flags[] = {
	SF(MAP_SHARED),
	SF(MAP_PRIVATE),
	SF(MAP_FIXED),
	SF(MAP_ANONYMOUS),
	SF(MAP_GROWSDOWN),
	SF(MAP_DENYWRITE),
	SF(MAP_EXECUTABLE),
	SF(MAP_LOCKED),
	SEND,
};

STRACE_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
	       unsigned long, prot, unsigned long, flags,
	       unsigned long, fd, unsigned long, off)
{
	unsigned char buf_prot[128];
	unsigned char buf_flags[128];
	struct file *f = NULL;

	memset(buf_prot, 0, 128);
	memset(buf_flags, 0, 128);
	strace_printflags(sf_mmap_prot, prot, buf_prot);
	strace_printflags(sf_mmap_flags, flags, buf_flags);

	if (!(flags & MAP_ANONYMOUS))
		f = fdget(fd);

	sp("addr=%#lx, len=%#lx, prot(%#lx)=%s, flags(%#lx)=%s, fd=%lu(%s), off=%#lx",
		addr, len, prot, buf_prot, flags, buf_flags, fd, f ? f->f_name : " ", off);

	if (f)
		put_file(f);
}

STRACE_DEFINE2(munmap, unsigned long, addr, size_t, len)
{
	sp("[%#lx - %#lx], %zu", addr, addr + len, len);
}

STRACE_DEFINE3(mprotect, unsigned long, start, size_t, len,
	       unsigned long, prot)
{
	unsigned char buf_prot[128];

	memset(buf_prot, 0, 128);
	strace_printflags(sf_mmap_prot, prot, buf_prot);

	sp("start=%#lx, len=%#lx, prot(%#lx)=%s",
		start, len, prot, buf_prot);
}
