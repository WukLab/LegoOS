/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_PTRACE_H_
#define _ASM_X86_PTRACE_H_

#ifndef __ASSEMBLY__

struct pt_regs {
	/*
	 * C ABI says these regs are callee-preserved.
	 * They aren't saved on kernel entry unless syscall needs a complete,
	 * fully filled "struct pt_regs".
	 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;

	/*
	 * These regs are callee-clobbered
	 * Always saved on kernel entry
	 */
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

	/* top of stack page */
};

static inline unsigned long
kernel_stack_pointer(struct pt_regs *regs)
{
	return regs->sp;
}

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_PTRACE_H_ */
