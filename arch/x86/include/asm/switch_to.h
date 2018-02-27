/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_SWITCH_TO_H_
#define _ASM_X86_SWITCH_TO_H_

#include <asm/ptrace.h>

/*
 * This is the structure pointed to by thread.sp for an inactive task.  The
 * order of the fields must match the code in __switch_to_asm().
 */
struct inactive_task_frame {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bx;
	unsigned long bp;

	/*
	 * ret_addr:
	 *
	 * 1) Next instruction after __switch_to_asm(),
	 *    this is pushed by hardware when we call __switch_to_asm()
	 *
	 * 2) ret_from_fork, explicitly assigned inside copy_thread_tls()
	 */
	unsigned long ret_addr;
};

struct fork_frame {
	struct inactive_task_frame	frame;
	struct pt_regs			regs;
};

asmlinkage void ret_from_fork(void);

struct task_struct;

struct task_struct *__switch_to_asm(struct task_struct *prev,
				    struct task_struct *next);

struct task_struct *__switch_to(struct task_struct *prev,
				struct task_struct *next);

/*
 * Quick fact:
 * The @last is assigned after the switching thread got resumed next time.
 * The __switch_to_asm() is executed in the current switching thread, but
 * the assignment to @(last) happens after this switching thread got resumed
 * later. With this, every thread can know who do the switch to them.
 *
 * The way schedule() call swicth_to(): the @last equals @prev, so @prev will
 * be overrided, so the current switching thread can know who did the switch
 * to him.
 */
#define switch_to(prev, next, last)			\
do {							\
	(last) = __switch_to_asm((prev), (next));	\
} while (0)

#endif /* _ASM_X86_SWITCH_TO_H_ */
