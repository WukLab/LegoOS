/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * CPU idle with:
 *	Preempt disabled
 *	Interrupt enabled
 */

#include <lego/sched.h>
#include <lego/kernel.h>

#include "sched.h"

/* Weak implementations for optional arch specific functions */
void __weak arch_cpu_idle_enter(void) { }
void __weak arch_cpu_idle(void) { }

void cpu_idle(void)
{
	while (1)  {
		while (!need_resched()) {
			/* NOTE: no locks or semaphores should be used here */
			arch_safe_halt();
		}

		schedule_preempt_disabled();
	}
}
