/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_CHECKPOINT_H_
#define _LEGO_CHECKPOINT_H_

#include <lego/types.h>
#include <lego/ptrace.h>

struct ss_file {

};

struct ss_files {

};

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
};

struct snapshot {
	
};

#endif /* _LEGO_CHECKPOINT_H_ */
