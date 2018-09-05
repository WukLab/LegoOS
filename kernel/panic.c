/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/asm.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/ptrace.h>
#include <lego/atomic.h>
#include <lego/profile.h>
#include <lego/fit_ibapi.h>
#include <processor/pcache.h>
#include <processor/processor.h>

/*
 * 64-bit random ID for oopses:
 */
static u64 oops_id;

void print_oops_end_marker(void)
{
	pr_warn("---[ end trace %016llx ]---\n", (unsigned long long)oops_id++);
}

struct warn_args {
	const char *fmt;
	va_list args;
};

static DEFINE_SPINLOCK(warn_lock);

static void __warn(const char *file, int line, void *caller,
		   struct pt_regs *regs, struct warn_args *args)
{
	unsigned long flags;

	spin_lock_irqsave(&warn_lock, flags);
	pr_warn("------------[ cut here ]------------\n");

	if (file)
		pr_warn("WARNING: CPU: %d PID: %d at %s:%d %pS\n",
			smp_processor_id(), current->pid, file, line,
			caller);
	else
		pr_warn("WARNING: CPU: %d PID: %d at %pS\n",
			smp_processor_id(), current->pid, caller);

	if (args)
		vprintk(args->fmt, args->args);

	if (regs)
		show_regs(regs);
	else
		dump_stack();

	print_oops_end_marker();
	spin_unlock_irqrestore(&warn_lock, flags);
}

void warn_slowpath_fmt(const char *file, int line, const char *fmt, ...)
{
	struct warn_args args;

	args.fmt = fmt;
	va_start(args.args, fmt);
	__warn(file, line, __builtin_return_address(0), NULL, &args);
	va_end(args.args);
}

void warn_slowpath_null(const char *file, int line)
{
	__warn(file, line, __builtin_return_address(0), NULL, NULL);
}

/*
 * panic_cpu is used for synchronizing panic() execution.
 * It holds a CPU number which is executing panic() currently. A value of
 * PANIC_CPU_INVALID means no CPU has entered panic().
 */
#define PANIC_CPU_INVALID -1
atomic_t panic_cpu = ATOMIC_INIT(PANIC_CPU_INVALID);

void panic_smp_self_stop(void)
{
	while (1)
		cpu_relax();
}

void panic(const char *fmt, ...)
{
	char buf[1024];
	va_list args;
	unsigned int this_cpu, old_cpu;

	local_irq_disable();

	/*
	 * Only one CPU is allowed to execute panic().
	 * The 1st CPU will print the message and send halt to other CPUs.
	 */
	this_cpu = smp_processor_id();
	old_cpu = atomic_cmpxchg(&panic_cpu, PANIC_CPU_INVALID, this_cpu);

	if (old_cpu != PANIC_CPU_INVALID && old_cpu != this_cpu)
		panic_smp_self_stop();

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	pr_emerg("Kernel Panic - not syncing: %s\n", buf);
	show_general_task_info(current);
	show_stack_content(current, NULL, NULL);
	show_call_trace(current, NULL, NULL);

	smp_send_stop();
	pr_emerg("---[ end Kernel panic - not syncing: %s\n", buf);

	/* Print short info on all tasks */
	if (scheduler_state == SCHED_UP)
		show_state_filter(0, true);

	if (manager_state == MANAGER_UP) {
		exit_processor_strace(current);
		print_pcache_events();
		print_profile_points();
		dump_ib_stats();
	}

	for (;;)
		hlt();
}
