/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_SPINLOCK_H_
#define _ASM_X86_SPINLOCK_H_

typedef struct arch_spinlock {
	unsigned int slock;
} arch_spinlock_t;

#define __ARCH_SPIN_LOCK_UNLOCKED { 1U }

static __always_inline void arch_spin_lock(arch_spinlock_t *lock)
{
	asm volatile (
		"1:			\n\t"
		"	lock; decb %0	\n\t"
		"	jns 3f		\n\t"
		"2:			\n\t"
		"	rep; nop	\n\t"
		"	cmpb $0, %0	\n\t"
		"	jle 2b		\n\t"
		"	jmp 1b		\n\t"
		"3:			\n\t"
		: "+m" (lock->slock)
		: : "memory"
	);
}

static __always_inline void arch_spin_unlock(arch_spinlock_t *lock)
{
	asm volatile (
		"movl $1, %0"
		: "+m" (lock->slock)
		: : "memory"
	);
}

static __always_inline int arch_spin_trylock(arch_spinlock_t *lock)
{
	char oldval;
	asm volatile(
		"xchgb %b0, %1"
		: "=q" (oldval), "+m" (lock->slock)
		: "0" (0)
		: "memory"
	);
	return oldval > 0;
}

static __always_inline int arch_spin_is_locked(arch_spinlock_t *lock)
{
	return *(volatile signed char *)(&(lock)->slock) <= 0;
}

#endif /* _ASM_X86_SPINLOCK_H_ */
