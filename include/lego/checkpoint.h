/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_CHECKPOINT_H_
#define _LEGO_CHECKPOINT_H_

#include <lego/files.h>
#include <lego/sched.h>
#include <lego/ptrace.h>

struct ss_files {
	unsigned int		fd;
	unsigned int		f_mode;
	unsigned int		f_flags;
	unsigned long		f_pos;
	char			f_name[FILENAME_LEN_DEFAULT];
} __packed;

struct ss_thread_gregs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;

	/*
	 * On syscall entry, this is syscall#.
	 * On CPU exception, this is error code.
	 * On hw interrupt, it's IRQ number:
	 */
	unsigned long orig_ax;

	/* Return frame for iretq */
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;

	unsigned long fs_base;
	unsigned long gs_base;
	unsigned long ds;
	unsigned long es;

	/* aka. fsindex, gsindex */
	unsigned long fs;
	unsigned long gs;
} __packed;

struct ss_thread_fpregs {

} __packed;

struct ss_thread_regs {
	struct ss_thread_gregs	gregs;
	struct ss_thread_fpregs	fpregs;
} __packed;

struct ss_task_struct {
	pid_t			pid;
	struct ss_thread_regs	user_regs;

	int __user		*set_child_tid;
	int __user		*clear_child_tid;

	unsigned long		sas_ss_sp;
	size_t			sas_ss_size;
	unsigned		sas_ss_flags;
} __packed;

struct process_snapshot {
	struct ss_task_struct	*tasks;
	unsigned int		nr_tasks;
	char			comm[TASK_COMM_LEN];

	struct ss_files		*files;
	unsigned int		nr_files;

	/*
	 * All pending signals MUST be handled
	 * before checkpointing. Hence we do not
	 * need to save private/shared pending signals.
	 */
	struct sigaction	action[_NSIG];
	sigset_t		blocked;

	struct list_head	list;
};

void enqueue_pss(struct process_snapshot *pss);
struct process_snapshot *dequeue_pss(void);

struct task_struct *
restore_process_snapshot(struct process_snapshot *pss);

void dump_process_snapshot_files(struct process_snapshot *pss);
void dump_process_snapshot_signals(struct process_snapshot *pss);
void dump_process_snapshot_thread(struct ss_task_struct *t);
void dump_process_snapshot_threads(struct process_snapshot *pss);

#define DUMP_SS_SIGNAL	0x1
void dump_process_snapshot(struct process_snapshot *pss, const char *who, int dump_flags);

#endif /* _LEGO_CHECKPOINT_H_ */
