/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_RWSEM_H_
#define _LEGO_RWSEM_H_

#include <lego/atomic.h>
#include <lego/spinlock.h>

/*
 * the rw-semaphore definition
 * - if count is 0 then there are no active readers or writers
 * - if count is +ve then that is the number of active readers
 * - if count is -1 then there is one active writer
 * - if wait_list is not empty, then there are processes waiting for the semaphore
 */
struct rw_semaphore {
	atomic_long_t		count;
	struct list_head	wait_list;
	spinlock_t		wait_lock;
};

#include <asm/rwsem.h>

#define __RWSEM_INITIALIZER(name) {				  \
		.count = ATOMIC_LONG_INIT(RWSEM_UNLOCKED_VALUE)	  \
		.wait_list = LIST_HEAD_INIT((name).wait_list),	  \
		.wait_lock = __SPIN_LOCK_UNLOCKED(name.wait_lock) \
	}

#define DEFINE_RWSEM(name) \
	struct rw_semaphore name = __RWSEM_INITIALIZER(name)

static inline void init_rwsem(struct rw_semaphore *sem)
{
	atomic_long_set(&sem->count, RWSEM_UNLOCKED_VALUE);
	INIT_LIST_HEAD(&sem->wait_list);
	spin_lock_init(&sem->wait_lock);
}

/* In all implementations count != 0 means locked */
static inline int rwsem_is_locked(struct rw_semaphore *sem)
{
	return atomic_long_read(&sem->count) != 0;
}

/*
 * This is the same regardless of which rwsem implementation that is being used.
 * It is just a heuristic meant to be called by somebody alreadying holding the
 * rwsem to see if somebody from an incompatible type is wanting access to the
 * lock.
 */
static inline int rwsem_is_contended(struct rw_semaphore *sem)
{
	return !list_empty(&sem->wait_list);
}

/*
 * lock for reading
 */
static inline void down_read(struct rw_semaphore *sem)
{

}

/*
 * trylock for reading -- returns 1 if successful, 0 if contention
 */
static inline int down_read_trylock(struct rw_semaphore *sem)
{
	return 1;
}

/*
 * lock for writing
 */
static inline void down_write(struct rw_semaphore *sem)
{

}

static inline int __must_check down_write_killable(struct rw_semaphore *sem)
{
	return 0;
}

/*
 * trylock for writing -- returns 1 if successful, 0 if contention
 */
static inline int down_write_trylock(struct rw_semaphore *sem)
{
	return 1;
}

/*
 * release a read lock
 */
static inline void up_read(struct rw_semaphore *sem)
{

}

/*
 * release a write lock
 */
static inline void up_write(struct rw_semaphore *sem)
{

}

#endif /* _LEGO_RWSEM_H_ */
