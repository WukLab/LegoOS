/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/kernel.h>

/* Weak implementations for optional arch specific functions */
void __weak arch_cpu_idle_enter(void) { }
void __weak arch_cpu_idle(void) { }

static void do_idle(void)
{
	while (!need_resched()) {
		/* NOTE: no locks or semaphores should be used here */
		arch_safe_halt();
	}

	schedule();
}

void cpu_idle(void)
{
	while (1)
		do_idle();
}
