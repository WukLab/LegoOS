/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/rwsem.h>
#include <lego/kernel.h>

/*
 * lock for reading
 */
void __sched down_read(struct rw_semaphore *sem)
{
	might_sleep();
	__down_read(sem);
	rwsem_set_reader_owned(sem);
}

/*
 * trylock for reading -- returns 1 if successful, 0 if contention
 */
int down_read_trylock(struct rw_semaphore *sem)
{
	int ret = __down_read_trylock(sem);

	if (ret == 1)
		rwsem_set_reader_owned(sem);
	return ret;
}

/*
 * lock for writing
 */
void __sched down_write(struct rw_semaphore *sem)
{
	might_sleep();

	__down_write(sem);
	rwsem_set_owner(sem);
}

/*
 * lock for writing
 */
int __sched down_write_killable(struct rw_semaphore *sem)
{
	might_sleep();

	if (__down_write_killable(sem))
		return -EINTR;

	rwsem_set_owner(sem);
	return 0;
}

/*
 * trylock for writing -- returns 1 if successful, 0 if contention
 */
int down_write_trylock(struct rw_semaphore *sem)
{
	int ret = __down_write_trylock(sem);

	if (ret == 1)
		rwsem_set_owner(sem);
	return ret;
}

/*
 * release a read lock
 */
void up_read(struct rw_semaphore *sem)
{
	__up_read(sem);
}

/*
 * release a write lock
 */
void up_write(struct rw_semaphore *sem)
{
	rwsem_clear_owner(sem);
	__up_write(sem);
}

/*
 * downgrade write lock to read lock
 */
void downgrade_write(struct rw_semaphore *sem)
{
	/*
	 * lockdep: a downgraded write will live on as a write
	 * dependency.
	 */
	rwsem_set_reader_owned(sem);
	__downgrade_write(sem);
}
