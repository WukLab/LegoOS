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

static struct strace_flag sf_clone[] = {
	SF(CLONE_VM),
	SF(CLONE_FS),
	SF(CLONE_FILES),
	SF(CLONE_SIGHAND),
	SF(CLONE_PTRACE),
	SF(CLONE_VFORK),
	SF(CLONE_PARENT),
	SF(CLONE_THREAD),
	SF(CLONE_NEWNS),
	SF(CLONE_SYSVSEM),
	SF(CLONE_SETTLS),
	SF(CLONE_PARENT_SETTID),
	SF(CLONE_CHILD_CLEARTID),
	SF(CLONE_DETACHED),
	SF(CLONE_UNTRACED),
	SF(CLONE_CHILD_SETTID),
	SF(CLONE_NEWCGROUP),
	SF(CLONE_NEWUTS),
	SF(CLONE_NEWIPC),
	SF(CLONE_NEWUSER),
	SF(CLONE_NEWPID),
	SF(CLONE_NEWNET),
	SF(CLONE_IO),
	SF(CLONE_IDLE_THREAD),
	SF(CLONE_GLOBAL_THREAD),
	SEND,
};

STRACE_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,
		 int __user *, parent_tidptr,
		 int __user *, child_tidptr,
		 unsigned long, tls)
{
	unsigned char buf[128];

	memset(buf, 0, 128);
	strace_printflags(sf_clone, clone_flags, buf);

	sp("flags(%#lx)=%s, newsp=%#lx, parent_tidptr=%p, child_tidptr=%p, tls=%#lx",
		clone_flags, buf, newsp, parent_tidptr, child_tidptr, tls);
}

STRACE_DEFINE0(fork)
{
	sp("current: pid=%d tgid=%d comm=%s", current->pid, current->tgid, current->comm);
}

static struct strace_flag sf_waitid_which[] = {
	SF(P_ALL),
	SF(P_PID),
	SF(P_PGID),
	SEND,
};

/* Used by both waitid and wait4 */
static struct strace_flag sf_waitid_options[] = {
	SF(WNOHANG),
	SF(WUNTRACED),
	SF(WSTOPPED),
	SF(WEXITED),
	SF(WCONTINUED),
	SF(WNOWAIT),
	SF(__WNOTHREAD),
	SF(__WALL),
	SF(__WCLONE),
	SEND,
};

STRACE_DEFINE5(waitid, int, which, pid_t, upid, struct siginfo __user *, infop,
	       int, options, struct rusage __user *, ru)
{
	unsigned char buf_which[16];
	unsigned char buf_options[128];

	memset(buf_which, 0, 16);
	memset(buf_options, 0, 128);
	strace_printflags(sf_waitid_which, options, buf_which);
	strace_printflags(sf_waitid_options, options, buf_options);

	sp("while(%d)=%s, upid=%d, siginfo=%p, options(%#x)=%s, ru=%p",
		which, buf_which, upid, infop, options, buf_options, ru);
}

STRACE_DEFINE4(wait4, pid_t, upid, int __user *, stat_addr,
	       int, options, struct rusage __user *, ru)
{
	unsigned char buf_options[128];

	memset(buf_options, 0, 128);
	strace_printflags(sf_waitid_options, options, buf_options);
	sp("upid=%d, stat_addr=%p, options(%#x)=%s, ru=%p",
		upid, stat_addr, options, buf_options, ru);
}

STRACE_DEFINE0(getpid)
{
	sp("current: %d, tgid: %d", current->pid, current->tgid);
}

STRACE_DEFINE1(set_tid_address, int __user *, tidptr)
{
	sp("tidptr=%p", tidptr);
}
