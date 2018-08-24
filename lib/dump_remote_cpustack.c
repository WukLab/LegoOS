/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/smp.h>
#include <lego/kernel.h>
#include <asm/irq_regs.h>

/*
 * This is only valid if DEBUG_KERNEL is ON.
 * Because by default call_function handler will not save pt_regs.
 */
static void cpu_dumpstack_func(void *info)
{
	struct pt_regs *regs = get_irq_regs();
	show_regs(regs);
}

void cpu_dumpstack(int cpu)
{
	smp_call_function_single(cpu, cpu_dumpstack_func, NULL, 1);
}
