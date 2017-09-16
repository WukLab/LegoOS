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

	if (unlikely(memcmp(curr, saved, sizeof(*saved)))) {
		int nr = saved->orig_ax;

		/* gocha! */
		pr_err("Saved pt_regs:\n");
		show_regs(saved);

		pr_err("Current corrupted pt_regs:\n");
		show_regs(curr);
		panic("Catched buggy SYSCALL: %pS",
			sys_call_table[nr]);
	}

	if (WARN_ON(!irqs_disabled()))
		local_irq_disable();
}
