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

void panic(const char *fmt, ...)
{
	char buf[1024];
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	pr_emerg("Kernel Panic - : %s\n", buf);
	show_regs(current_pt_regs());
	pr_emerg("---[ end Kernel panic - not syncing: %s\n", buf);

	hlt();
}
