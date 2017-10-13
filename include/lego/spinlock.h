/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Spinlock is used to protect your critical code.
 *
 * Preemption is disabled before acquiring the lock, otherwise it's prone
 * to reach deadlock state. Use the disable irq version if you must have
 * an atomic context.
 *
 * It is dangerous and not efficient to run any *non-atomic* code, such as
 * sleep(), disk op inside critical section protected by spinlock.
 *
 * Great article at: www.makelinux.net/ldd3/chp-5-sect-5
 */

#ifndef _LEGO_SPINLOCK_H_
#define _LEGO_SPINLOCK_H_

#include <lego/irq.h>
#include <lego/preempt.h>
#include <lego/typecheck.h>

#include <asm/spinlock.h>
#include <asm/barrier.h>

typedef struct spinlock {
	arch_spinlock_t arch_lock;
#ifdef CONFIG_DEBUG_SPINLOCK
	int magic, owner_cpu;
	void *owner;
#endif
} spinlock_t;

#define SPINLOCK_MAGIC 0xdead4ead

#ifdef CONFIG_DEBUG_SPINLOCK
# define SPIN_DEBUG_INIT(lock)				\
	.magic		= SPINLOCK_MAGIC,		\
	.owner_cpu	= -1,				\
	.owner		= (void *)(-1L)
#else
# define SPIN_DEBUG_INIT(lock)
#endif

#define __SPIN_LOCK_INIT(lockname)			\
{							\
	.arch_lock = __ARCH_SPIN_LOCK_UNLOCKED,		\
	SPIN_DEBUG_INIT(lockname)			\
}

#define __SPIN_LOCK_UNLOCKED(lock)			\
	(spinlock_t) __SPIN_LOCK_INIT(lock)

#define DEFINE_SPINLOCK(lock)				\
	spinlock_t lock = __SPIN_LOCK_UNLOCKED(lock)

#define spin_lock_init(lock)				\
	do {						\
		*(lock) = __SPIN_LOCK_UNLOCKED((lock));	\
	} while (0)

static inline void spin_lock(spinlock_t *lock)
{
	preempt_disable();
	arch_spin_lock(&lock->arch_lock);
}

static inline void spin_lock_irq(spinlock_t *lock)
{
	local_irq_disable();
	preempt_disable();
	arch_spin_lock(&lock->arch_lock);
}

#define spin_lock_irqsave(lock, flags)			\
	do {						\
		typecheck(unsigned long, (flags));	\
		local_irq_save((flags));		\
		preempt_disable();			\
		arch_spin_lock(&(lock)->arch_lock);	\
	} while (0)

static inline void spin_unlock(spinlock_t *lock)
{
	arch_spin_unlock(&lock->arch_lock);
	preempt_enable();
}

static inline void spin_unlock_irq(spinlock_t *lock)
{
	arch_spin_unlock(&lock->arch_lock);
	local_irq_enable();
	preempt_enable();
}

static inline void spin_unlock_irqrestore(spinlock_t *lock,  unsigned long flags)
{
	arch_spin_unlock(&lock->arch_lock);
	local_irq_restore(flags);
	preempt_enable();
}

static inline int spin_trylock(spinlock_t *lock)
{
	preempt_disable();
	if (arch_spin_trylock(&lock->arch_lock))
		return 1;
	preempt_enable();
	return 0;
}

static inline int spin_trylock_irq(spinlock_t *lock)
{
	local_irq_disable();
	preempt_disable();
	if (arch_spin_trylock(&lock->arch_lock))
		return 1;
	local_irq_enable();
	preempt_enable();
	return 0;
}

#define spin_trylock_irqsave(lock, flags)		\
({							\
	typecheck(unsigned long, (flags));		\
	local_irq_save((flags));			\
	preempt_disable();				\
	arch_spin_trylock(&(lock)->arch_lock) ? 1 :	\
	({						\
		local_irq_restore((flags));		\
		preempt_enable();			\
		0;					\
	});						\
})

static inline int spin_is_locked(spinlock_t *lock)
{
	return arch_spin_is_locked(&lock->arch_lock);
}

#endif /* _LEGO_SPINLOCK_H_ */
