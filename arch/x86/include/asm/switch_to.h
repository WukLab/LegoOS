/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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

	/*
	 * These two fields must be together.
	 * They form a stack frame header, needed by get_frame_pointer().
	 */
	unsigned long bp;
	unsigned long ret_addr;
};

struct fork_frame {
	struct inactive_task_frame	frame;
	struct pt_regs			regs;
};

asmlinkage void ret_from_fork(void);

#endif /* _ASM_X86_SWITCH_TO_H_ */
