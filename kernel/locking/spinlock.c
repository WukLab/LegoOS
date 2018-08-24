/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/spinlock.h>

#define SEC_20	(20000000000)

/*
 * These functions are called within spin_*().
 * So we should only use arch_spin_*() within them.
 */

void report_deadlock(spinlock_t *lock)
{
	pr_info("------------------- cut here -------------------\n");
	pr_info("Possible deadlock happend\n");
	pr_info("Current call stack:\n");
	dump_stack();

	pr_info("Owner CPU %d:\n", lock->owner_cpu);
	if (!cpu_online(lock->owner_cpu))
		pr_info("  BUG! The CPU is offline\n");

	cpu_dumpstack(lock->owner_cpu);
}

void debug_spin_lock(spinlock_t *lock)
{
	unsigned long start_ns, now;

	start_ns = sched_clock();
	while (!arch_spin_trylock(&lock->arch_lock)) {
		now = sched_clock();

		if ((now - start_ns) > SEC_20) {
			report_deadlock(lock);
			hlt();
		}
	}

	/* Got it. Setup */
	lock->owner_cpu = smp_processor_id();
	lock->owner = current;
	lock->ip = __builtin_return_address(0);
	barrier();
}

void debug_spin_unlock(spinlock_t *lock)
{
	if (lock->owner_cpu == -1 || lock->owner == NULL) {
		pr_info("owner   cpu: %2d owner: %p ip: %pF\n",
			lock->owner_cpu, lock->owner, lock->ip);
		pr_info("release cpu: %2d owner: %p ip: %pF\n",
			lock->release_cpu, lock->release_owner, lock->release_ip);
		dump_stack();
	}

	lock->owner_cpu = -1;
	lock->owner = NULL;
	lock->ip = 0;

	lock->release_cpu = smp_processor_id();
	lock->release_owner = current;
	lock->release_ip = __builtin_return_address(0);
	barrier();

	arch_spin_unlock(&lock->arch_lock);
}
