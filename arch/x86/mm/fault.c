/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/traps.h>
#include <asm/ptrace.h>

#include <lego/panic.h>
#include <lego/printk.h>
#include <lego/kernel.h>

dotraplinkage void do_page_fault(struct pt_regs *regs, long error_code)
{
	panic("page fault");
}
