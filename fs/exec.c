/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/ptrace.h>
#include <lego/kernel.h>

unsigned long stack[8];

void user_level_program(void)
{
	hlt();
}

int do_execve(const char *filename,
	      const char * const *argv,
	      const char * const *envp)
{
	struct pt_regs *regs = current_pt_regs();

	start_thread(regs, (unsigned long)0xC0001000, (unsigned long)&stack[4]);
	return 0;
}
