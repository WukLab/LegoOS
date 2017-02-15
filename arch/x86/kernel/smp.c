/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/ipi.h>
#include <asm/apic.h>
#include <asm/hw_irq.h>
#include <asm/ptrace.h>

#include <lego/kernel.h>

asmlinkage __visible void
reboot_interrupt(struct pt_regs *regs)
{
	pr_info("reboot_interrupt");
}

asmlinkage __visible void
call_function_single_interrupt(struct pt_regs *regs)
{
	pr_info("call_function_interrupt");
}

asmlinkage __visible void
call_function_interrupt(struct pt_regs *regs)
{
	pr_info("call_function_interrupt");
}
