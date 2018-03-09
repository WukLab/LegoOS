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
#include <processor/fs.h>
#include <generated/asm-offsets.h>
#include <generated/unistd_64.h>

#define sp(fmt, ...)	\
	pr_info("%s cpu%d " fmt "\n", __func__, smp_processor_id(), __VA_ARGS__)

void strace_enter_default(unsigned long nr, unsigned long a1, unsigned long a2,
			  unsigned long a3, unsigned long a4, unsigned long a5, unsigned long a6)
{
	pr_info("CPU%d PID%d %pS\n", smp_processor_id(), current->pid, sys_call_table[nr]);
}

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

STRACE_DEFINE3(mprotect, unsigned long, start, size_t, len,
	       unsigned long, prot)
{
	unsigned char buf_prot[128];

	memset(buf_prot, 0, 128);
	strace_printflags(sf_mmap_prot, prot, buf_prot);

	sp("start=%#lx, len=%#lx, prot(%#lx)=%s",
		start, len, prot, buf_prot);
}

void strace_printflags(struct strace_flag *sf, unsigned long flags, unsigned char *buf)
{
	int n = 0;
	int offset;

	if (WARN_ON(!sf || !buf))
		return;

	for (; (flags || !n) && sf->str; ++sf) {
		if ((flags == sf->val) ||
		    (sf->val && (flags & sf->val) == sf->val)) {
			offset = sprintf(buf, "%s%s", (n++ ? "|" : ""), sf->str);
			buf += offset;

			flags &= ~sf->val;
		}
		if (!flags)
			break;
	}
}

const strace_call_ptr_t strace_call_table[__NR_syscall_max+1] = {
	[0 ... __NR_syscall_max]	= &strace_enter_default,

	[__NR_clone]			= (strace_call_ptr_t)&strace__clone,
	[__NR_wait4]			= (strace_call_ptr_t)&strace__wait4,
	[__NR_waitid]			= (strace_call_ptr_t)&strace__waitid,
	[__NR_mmap]			= (strace_call_ptr_t)&strace__mmap,
	[__NR_mprotect]			= (strace_call_ptr_t)&strace__mprotect,
};

void strace_enter(struct pt_regs *regs)
{
	unsigned long nr = regs->orig_ax;
	unsigned long a1 = regs->di;
	unsigned long a2 = regs->si;
	unsigned long a3 = regs->dx;
	unsigned long a4 = regs->r10;
	unsigned long a5 = regs->r8;
	unsigned long a6 = regs->r9;

	if (likely(nr < NR_syscalls))
		strace_call_table[nr](nr, a1, a2, a3, a4, a5, a6);
}

void strace_exit(struct pt_regs *regs)
{
}
