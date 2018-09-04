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

static DEFINE_SPINLOCK(dump_lock);

void report_deadlock(spinlock_t *lock)
{
	arch_spin_lock(&dump_lock.arch_lock);

	pr_info("------------------- cut here -------------------\n");
	pr_info("Possible deadlock happend locker_cpu: %d\n", lock->owner_cpu);
	pr_info("Current call stack:\n");
	dump_stack();

	arch_spin_unlock(&dump_lock.arch_lock);

	if (lock->owner_cpu != -1)
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
	smp_wmb();
	lock->owner_cpu = smp_processor_id();
}

void debug_spin_unlock(spinlock_t *lock)
{
	lock->owner_cpu = -1;
	smp_wmb();
	arch_spin_unlock(&lock->arch_lock);
}
