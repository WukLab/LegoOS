/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_SPINLOCK_H_
#define _LEGO_SPINLOCK_H_

#include <lego/irq.h>
#include <lego/typecheck.h>

/* Arch-specific spinlock */
#include <asm/spinlock.h>

typedef struct spinlock {
	arch_spinlock_t arch_lock;
} spinlock_t;

#define __SPIN_LOCK_INIT(x)				\
{							\
	.arch_lock = __ARCH_SPIN_LOCK_UNLOCKED,		\
}

#define __SPIN_LOCK_UNLOCKED(x)	(spinlock_t) __SPIN_LOCK_INIT(x)

#define DEFINE_SPINLOCK(x)	spinlock_t x = __SPIN_LOCK_UNLOCKED(x)

#define spin_lock_init(lock)				\
	do {						\
		*(lock) = __SPIN_LOCK_UNLOCKED((lock));	\
	} while (0)
	
static inline void spin_lock(spinlock_t *lock)
{
	arch_spin_lock(&lock->arch_lock);
}

static inline void spin_lock_irq(spinlock_t *lock)
{
	local_irq_disable();
	arch_spin_lock(&lock->arch_lock);
}

#define spin_lock_irqsave(lock, flags)			\
	do {						\
		typecheck(unsigned long, (flags));	\
		local_irq_save((flags));		\
		arch_spin_lock(&(lock)->arch_lock);	\
	} while (0)

static inline void spin_unlock(spinlock_t *lock)
{
	arch_spin_unlock(&lock->arch_lock);
}

static inline void spin_unlock_irq(spinlock_t *lock)
{
	arch_spin_unlock(&lock->arch_lock);
	local_irq_enable();
}

static inline void spin_unlock_irqrestore(spinlock_t *lock,  unsigned long flags)
{
	arch_spin_unlock(&lock->arch_lock);
	local_irq_restore(flags);
}

static inline int spin_trylock(spinlock_t *lock)
{
	if (arch_spin_trylock(&lock->arch_lock))
		return 1;
	return 0;
}

static inline int spin_trylock_irq(spinlock_t *lock)
{
	local_irq_disable();
	if (arch_spin_trylock(&lock->arch_lock))
		return 1;
	local_irq_enable();
	return 0;
}

#define spin_trylock_irqsave(lock, flags)		\
({							\
	typecheck(unsigned long, (flags));		\
	local_irq_save((flags));			\
	arch_spin_trylock(&(lock)->arch_flags) ? 1 :	\
	({						\
		local_irq_restore((flags));		\
		0;					\
	});						\
})

static inline int spin_is_locked(spinlock_t *lock)
{
	return arch_spin_is_locked(&lock->arch_lock);
}

#endif /* _LEGO_SPINLOCK_H_ */
