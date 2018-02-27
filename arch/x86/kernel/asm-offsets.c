/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/kbuild.h>
#include <lego/sched.h>

#define __SYSCALL_64(nr, sym, qual) [nr] = 1,
static char syscalls_64[] = {
#include <asm/syscalls_64.h>
};

/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed to extract
 * and format the required data.
 */

void GoSpurs(void)
{
	OFFSET(TI_flags, thread_info, flags);
	BLANK();

	OFFSET(TASK_threadsp, task_struct, thread.sp);
	OFFSET(TASK_addr_limit, task_struct, thread.addr_limit);
	BLANK();

	DEFINE(PTREGS_SIZE, sizeof(struct pt_regs));
	BLANK();

#define ENTRY(entry) OFFSET(pt_regs_ ## entry, pt_regs, entry)
	ENTRY(bx);
	ENTRY(cx);
	ENTRY(dx);
	ENTRY(sp);
	ENTRY(bp);
	ENTRY(si);
	ENTRY(di);
	ENTRY(r8);
	ENTRY(r9);
	ENTRY(r10);
	ENTRY(r11);
	ENTRY(r12);
	ENTRY(r13);
	ENTRY(r14);
	ENTRY(r15);
	ENTRY(flags);
	BLANK();
#undef ENTRY

	OFFSET(TSS_ist, tss_struct, x86_tss.ist);
	OFFSET(TSS_sp0, tss_struct, x86_tss.sp0);
	BLANK();

	DEFINE(__NR_syscall_max, sizeof(syscalls_64) - 1);
	DEFINE(NR_syscalls, sizeof(syscalls_64));
}
