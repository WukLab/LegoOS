/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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

	/* Only one CPU is allowed to execute panic(). The 1st CPU will
	 * print the message and send halt to other CPUs. */
	this_cpu = smp_processor_id();
	old_cpu = atomic_cmpxchg(&panic_cpu, PANIC_CPU_INVALID, this_cpu);

	if (old_cpu != PANIC_CPU_INVALID && old_cpu != this_cpu)
		panic_smp_self_stop();

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	pr_emerg("Kernel Panic - not syncing: %s\n", buf);
	show_regs(current_pt_regs());
	smp_send_stop();
	pr_emerg("---[ end Kernel panic - not syncing: %s\n", buf);

	hlt();
}
