/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * NOTE:
 * Linux has two different implementations: xadd and spinlock.
 * Lego currently is only using xadd version, which will need
 * arch-specific code. Please check asm/rwsem.h for more details.
 */

#ifndef _LEGO_RWSEM_H_
#define _LEGO_RWSEM_H_

#include <lego/list.h>
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

struct rw_semaphore *rwsem_down_read_failed(struct rw_semaphore *sem);
struct rw_semaphore *rwsem_down_write_failed(struct rw_semaphore *sem);
struct rw_semaphore *rwsem_down_write_failed_killable(struct rw_semaphore *sem);
struct rw_semaphore *rwsem_wake(struct rw_semaphore *);
struct rw_semaphore *rwsem_downgrade_wake(struct rw_semaphore *sem);

#include <asm/rwsem.h>

#define __RWSEM_INITIALIZER(name) {					\
		.count = ATOMIC_LONG_INIT(RWSEM_UNLOCKED_VALUE),	\
		.wait_list = LIST_HEAD_INIT((name).wait_list),		\
		.wait_lock = __SPIN_LOCK_UNLOCKED(name.wait_lock)	\
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
void down_read(struct rw_semaphore *sem);

/*
 * trylock for reading -- returns 1 if successful, 0 if contention
*/
int down_read_trylock(struct rw_semaphore *sem);

/*
 * lock for writing
 */
void down_write(struct rw_semaphore *sem);
int __must_check down_write_killable(struct rw_semaphore *sem);

/*
 * trylock for writing -- returns 1 if successful, 0 if contention
 */
int down_write_trylock(struct rw_semaphore *sem);

/*
 * release a read lock
 */
void up_read(struct rw_semaphore *sem);

/*
 * release a write lock
 */
void up_write(struct rw_semaphore *sem);

/*
 * downgrade write lock to read lock
 */
void downgrade_write(struct rw_semaphore *sem);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
#else
# define down_read_nested(sem, subclass)		down_read(sem)
# define down_write_nest_lock(sem, nest_lock)		down_write(sem)
# define down_write_nested(sem, subclass)		down_write(sem)
# define down_write_killable_nested(sem, subclass)	down_write_killable(sem)
# define down_read_non_owner(sem)			down_read(sem)
# define up_read_non_owner(sem)				up_read(sem)
#endif

#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
/*
 * The owner field of the rw_semaphore structure will be set to
 * RWSEM_READ_OWNED when a reader grabs the lock. A writer will clear
 * the owner field when it unlocks. A reader, on the other hand, will
 * not touch the owner field when it unlocks.
 *
 * In essence, the owner field now has the following 3 states:
 *  1) 0
 *     - lock is free or the owner hasn't set the field yet
 *  2) RWSEM_READER_OWNED
 *     - lock is currently or previously owned by readers (lock is free
 *       or not set by owner yet)
 *  3) Other non-zero value
 *     - a writer owns the lock
 */
#define RWSEM_READER_OWNED	((struct task_struct *)1UL)

/*
 * All writes to owner are protected by WRITE_ONCE() to make sure that
 * store tearing can't happen as optimistic spinners may read and use
 * the owner value concurrently without lock. Read from owner, however,
 * may not need READ_ONCE() as long as the pointer value is only used
 * for comparison and isn't being dereferenced.
 */
static inline void rwsem_set_owner(struct rw_semaphore *sem)
{
	WRITE_ONCE(sem->owner, current);
}

static inline void rwsem_clear_owner(struct rw_semaphore *sem)
{
	WRITE_ONCE(sem->owner, NULL);
}

static inline void rwsem_set_reader_owned(struct rw_semaphore *sem)
{
	/*
	 * We check the owner value first to make sure that we will only
	 * do a write to the rwsem cacheline when it is really necessary
	 * to minimize cacheline contention.
	 */
	if (sem->owner != RWSEM_READER_OWNED)
		WRITE_ONCE(sem->owner, RWSEM_READER_OWNED);
}

static inline bool rwsem_owner_is_writer(struct task_struct *owner)
{
	return owner && owner != RWSEM_READER_OWNED;
}

static inline bool rwsem_owner_is_reader(struct task_struct *owner)
{
	return owner == RWSEM_READER_OWNED;
}
#else
static inline void rwsem_set_owner(struct rw_semaphore *sem)
{
}

static inline void rwsem_clear_owner(struct rw_semaphore *sem)
{
}

static inline void rwsem_set_reader_owned(struct rw_semaphore *sem)
{
}
#endif /* CONFIG_RWSEM_SPIN_ON_OWNER */

#endif /* _LEGO_RWSEM_H_ */
