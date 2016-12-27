/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/ptrace.h>

#include <lego/irq.h>
#include <lego/kernel.h>

asmlinkage __visible unsigned int
do_IRQ(struct pt_regs *regs)
{
	pr_info("do_IRQ");
	return 0;
}

asmlinkage __visible void
x86_platform_ipi(struct pt_regs *regs)
{
	pr_info("x86_platform_ipi");
}
