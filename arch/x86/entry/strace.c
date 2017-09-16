/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * SYSCALL Tracer
 */

#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/ptrace.h>
#include <lego/syscalls.h>
#include <lego/comp_processor.h>
#include <generated/asm-offsets.h>

static DEFINE_PER_CPU(struct pt_regs, strace_regs);

static inline struct pt_regs *this_strace_regs(void)
{
	return this_cpu_ptr(&strace_regs);
}

/*
 * Enter with irq disabled
 */
void trace_syscall_enter(void)
{
	struct pt_regs *curr, *saved;

	if (WARN_ON(!irqs_disabled()))
		local_irq_disable();

	curr = current_pt_regs();
	saved = this_strace_regs();
	memcpy(saved, curr, sizeof(*saved));
}

static int compare_pt_regs(struct pt_regs *src, struct pt_regs *dst)
{
	int err = 0;

#define CMP_REG(reg)					\
do {							\
	if (src->reg != dst->reg) {			\
		pr_err("Unmatched %s\n", #reg);		\
		err = 1;				\
	}						\
} while (0)

	CMP_REG(r15);
	CMP_REG(r14);
	CMP_REG(r13);
	CMP_REG(r12);
	CMP_REG(bp);
	CMP_REG(bx);
	CMP_REG(r11);
	CMP_REG(r10);
	CMP_REG(r9);
	CMP_REG(r8);
	/* ax will be changed */
	CMP_REG(cx);
	CMP_REG(dx);
	CMP_REG(si);
	CMP_REG(di);
	/* orig_ax does not matter */
	CMP_REG(ip);
	CMP_REG(cs);
	CMP_REG(flags);
	CMP_REG(sp);
	CMP_REG(ss);

	return err;
#undef CMP_REG
}

/*
 * Enter with irq disabled
 */
void trace_syscall_exit(void)
{
	struct pt_regs *curr, *saved;

	if (WARN_ON(!irqs_disabled()))
		local_irq_disable();

	curr = current_pt_regs();
	saved = this_strace_regs();

	if (unlikely(compare_pt_regs(curr, saved))) {
		int nr = saved->orig_ax;

		/* gocha! */
		pr_err("Saved pt_regs:\n");
		__show_regs(saved, 0);

		pr_err("Current corrupted pt_regs:\n");
		__show_regs(curr, 0);
		panic("Catched buggy SYSCALL: %pS",
			sys_call_table[nr]);
	}

	if (WARN_ON(!irqs_disabled()))
		local_irq_disable();
}
