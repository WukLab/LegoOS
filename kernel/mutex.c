/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


#include <lego/sched.h>
#include <lego/mutex.h>
#include <lego/atomic.h>
#include <lego/kernel.h>

void __mutex_init(struct mutex *lock, const char *name)
{
	atomic_long_set(&lock->owner, 0);
	spin_lock_init(&lock->wait_lock);
	INIT_LIST_HEAD(&lock->wait_list);

#ifdef CONFIG_DEBUG_MUTEXES
	lock->magic = lock;
#endif
}

static noinline void __sched
__mutex_lock(struct mutex *lock, long state, unsigned long ip)
{

}

static noinline void __sched
__mutex_lock_slowpath(struct mutex *lock)
{
	__mutex_lock(lock, TASK_UNINTERRUPTIBLE, _RET_IP_);
}

/*
 * Release the lock, slowpath:
 */
static noinline void __sched
__mutex_unlock_slowpath(struct mutex *lock, unsigned long ip)
{
}

/*
 * Optimistic trylock that only works in the uncontended case. Make sure to
 * follow with a __mutex_trylock() before failing.
 */
static __always_inline bool __mutex_trylock_fast(struct mutex *lock)
{
	unsigned long curr = (unsigned long)current;

	if (!atomic_long_cmpxchg(&lock->owner, 0UL, curr))
		return true;

	return false;
}

static __always_inline bool __mutex_unlock_fast(struct mutex *lock)
{
	unsigned long curr = (unsigned long)current;

	if (atomic_long_cmpxchg(&lock->owner, curr, 0UL) == curr)
		return true;

	return false;
}

/**
 * mutex_lock - acquire the mutex
 * @lock: the mutex to be acquired
 *
 * Lock the mutex exclusively for this task. If the mutex is not
 * available right now, it will sleep until it can get it.
 *
 * The mutex must later on be released by the same task that
 * acquired it. Recursive locking is not allowed. The task
 * may not exit without first unlocking the mutex. Also, kernel
 * memory where the mutex resides must not be freed with
 * the mutex still locked. The mutex must first be initialized
 * (or statically defined) before it can be locked. memset()-ing
 * the mutex to 0 is not allowed.
 *
 * ( The CONFIG_DEBUG_MUTEXES .config option turns on debugging
 *   checks that will enforce the restrictions and will also do
 *   deadlock debugging. )
 *
 * This function is similar to (but not equivalent to) down().
 */
void __sched mutex_lock(struct mutex *lock)
{
	if (!__mutex_trylock_fast(lock))
		__mutex_lock_slowpath(lock);
}

/**
 * mutex_unlock - release the mutex
 * @lock: the mutex to be released
 *
 * Unlock a mutex that has been locked by this task previously.
 *
 * This function must not be used in interrupt context. Unlocking
 * of a not locked mutex is not allowed.
 *
 * This function is similar to (but not equivalent to) up().
 */
void __sched mutex_unlock(struct mutex *lock)
{
	if (__mutex_unlock_fast(lock))
		return;
	__mutex_unlock_slowpath(lock, _RET_IP_);
}
