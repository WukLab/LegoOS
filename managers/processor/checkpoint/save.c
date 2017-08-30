/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/pid.h>
#include <lego/timer.h>
#include <lego/ktime.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>
#include <lego/syscalls.h>
#include <lego/spinlock.h>
#include <lego/checkpoint.h>
#include <lego/timekeeping.h>

#include <asm/msr.h>

#include "internal.h"

static void save_thread_gregs(struct task_struct *p, struct ss_task_struct *ss)
{
	struct pt_regs *src = task_pt_regs(p);
	struct ss_thread_gregs *dst = &(ss->user_regs.gregs);
	unsigned long fs_base, gs_base;
	unsigned int ds, es, fs, gs;

#define COPY_REG(reg)	do { dst->reg = src->reg; } while (0)
	COPY_REG(r15);
	COPY_REG(r14);
	COPY_REG(r13);
	COPY_REG(r12);
	COPY_REG(bp);
	COPY_REG(bx);
	COPY_REG(r11);
	COPY_REG(r10);
	COPY_REG(r9);
	COPY_REG(r8);
	COPY_REG(ax);
	COPY_REG(cx);
	COPY_REG(dx);
	COPY_REG(si);
	COPY_REG(di);
	COPY_REG(orig_ax);
	COPY_REG(ip);
	COPY_REG(cs);
	COPY_REG(flags);
	COPY_REG(sp);
	COPY_REG(ss);
#undef COPY_REG

	asm("movl %%ds,%0" : "=r" (ds));
	asm("movl %%es,%0" : "=r" (es));
	asm("movl %%fs,%0" : "=r" (fs));
	asm("movl %%gs,%0" : "=r" (gs));

	rdmsrl(MSR_FS_BASE, fs_base);
	rdmsrl(MSR_GS_BASE, gs_base);

	dst->fs_base	= fs_base;
	dst->gs_base	= gs_base;
	dst->ds		= ds;
	dst->es		= es;
	dst->fs		= fs;
	dst->gs		= gs;
}

static void save_thread_fpregs(struct task_struct *p, struct ss_task_struct *ss)
{
}

void save_thread_regs(struct task_struct *p, struct ss_task_struct *ss)
{
	save_thread_gregs(p, ss);
	save_thread_fpregs(p, ss);
}

void save_open_files(struct task_struct *p, struct ss_task_struct *ss)
{
}
