/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/ptrace.h>
#include <lego/strace.h>
#include <lego/syscalls.h>
#include <generated/asm-offsets.h>

/*
 * This code used to detect buggy syscalls by comparing
 * the pt_regs before syscall invoked, and the pt_regs
 * after syscall finished.
 *
 * But I don't think we need to this to verify this.
 * Besides, some syscalls like execve(), sigreturn will
 * change the pt_regs.
 *
 * Well. I do not want to remove it.
 * 	- ys
 */

/* Ugly */
static struct strace *get_current_strace(void)
{
	struct strace *strace = current->strace;

	if (!strace) {
		strace = kmalloc(sizeof(*strace), GFP_KERNEL);
		if (strace)
			current->strace = strace;
	}
	return strace;
}

/*
 * Enter with irq disabled
 */
void trace_syscall_enter(void)
{
	struct strace *strace;
	struct pt_regs *curr, *saved;

	if (WARN_ON(!irqs_disabled()))
		local_irq_disable();

	strace = get_current_strace();
	if (!strace)
		return;

	curr = current_pt_regs();
	saved = &strace->regs;
	memcpy(saved, curr, sizeof(*saved));
	strace->enter_cpu = smp_processor_id();
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
	struct strace *strace = current->strace;
	struct pt_regs *curr, *saved;

	BUG_ON(!strace);
	if (WARN_ON(!irqs_disabled()))
		local_irq_disable();

	curr = current_pt_regs();
	saved = &strace->regs;

	if (unlikely(compare_pt_regs(curr, saved))) {
		int nr = saved->orig_ax;

		/* gotcha! */
		pr_err("Saved pt_regs:\n");
		show_regs(saved);

		pr_err("Current corrupted pt_regs:\n");
		show_regs(curr);
	}

	if (WARN_ON(!irqs_disabled()))
		local_irq_disable();
}
