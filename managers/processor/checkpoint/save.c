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

#ifdef CONFIG_CHECKPOINT_DEBUG
void paranoid_file_debug(struct task_struct *p, struct process_snapshot *ps)
{
	int i;
	struct ss_files *f, *ss_files = ps->files;

	debug("Saved files: %d\n", ps->nr_files);
	for (i = 0; i < ps->nr_files; i++) {
		f = &ss_files[i];

		debug("  fd=%d, f_name: %s\n", f->fd, f->f_name);
		debug("    f_mode:%x,f_flags:%x,f_pos:%lx\n",
			f->f_mode, f->f_flags, f->f_pos);
	}
}

void paranoid_signal_debug(struct task_struct *p, struct process_snapshot *ps)
{
	struct sigaction *action;
	int i;

	for (i = 0; i < _NSIG; i++) {
	
	}
}
#else
static inline void
paranoid_file_debug(struct task_struct *p, struct process_snapshot *ps) { }

static inline void
paranoid_signal_debug(struct task_struct *p, struct process_snapshot *ps) { }
#endif

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

void revert_save_open_files(struct task_struct *p, struct process_snapshot *ps)
{
	struct ss_files *ss_files = ps->files;

	BUG_ON(!ss_files);
	kfree(ss_files);
}

int save_open_files(struct task_struct *p, struct process_snapshot *ps)
{
	struct files_struct *files = p->files;
	struct ss_files *ss_files;
	unsigned int fd, nr_files;
	int i = 0;

	BUG_ON(p != p->group_leader);

	nr_files = bitmap_weight(files->fd_bitmap, NR_OPEN_DEFAULT);

	/* No open'ed files */
	if (nr_files == 0) {
		ps->files = NULL;
		ps->nr_files = 0;
		goto paranoid_debug;
	}

	ss_files = kmalloc(sizeof(*ss_files) * nr_files, GFP_KERNEL);
	if (unlikely(!ss_files))
		return -ENOMEM;

	for_each_set_bit(fd, files->fd_bitmap, NR_OPEN_DEFAULT) {
		struct ss_files *ss_file = &ss_files[i];
		struct file *file = files->fd_array[fd];

		BUG_ON(!file);

		ss_file->fd		= fd;
		ss_file->f_mode		= file->f_mode;
		ss_file->f_flags	= file->f_flags;
		ss_file->f_pos		= file->f_pos;
		memcpy(ss_file->f_name, file->f_name, FILENAME_LEN_DEFAULT);

		i++;
	}
	BUG_ON(i != nr_files);

	ps->files = ss_files;
	ps->nr_files = nr_files;

paranoid_debug:
	paranoid_file_debug(p, ps);
	return 0;
}

int save_signals(struct task_struct *p, struct process_snapshot *ps)
{
	struct k_sigaction *k_action = p->sighand->action;
	struct sigaction *src, *dst;
	int i;

	BUG_ON(p != p->group_leader);

	/* All signal actions */
	for (i = 0; i < _NSIG; i++) {
		src = &k_action[i].sa;
		dst = &ps->action[i];
		memcpy(dst, src, sizeof(*dst));
	}

	/* Bitmap for blocked signals */
	memcpy(&ps->blocked, &p->blocked, sizeof(sigset_t));

	paranoid_signal_debug(p, ps);

	return 0;
}
