/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_SEMAPHORE_H_
#define _LEGO_SEMAPHORE_H_

#include <lego/list.h>
#include <lego/spinlock.h>

/* Please don't access any members of this structure directly */
struct semaphore {
	spinlock_t		lock;
	unsigned int		count;
	struct list_head	wait_list;
};

#define __SEMAPHORE_INITIALIZER(name, n)				\
{									\
	.lock		= __SPIN_LOCK_UNLOCKED((name).lock),	\
	.count		= n,						\
	.wait_list	= LIST_HEAD_INIT((name).wait_list),		\
}

#define DEFINE_SEMAPHORE(name)	\
	struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)

static inline void sema_init(struct semaphore *sem, int val)
{
	*sem = (struct semaphore) __SEMAPHORE_INITIALIZER(*sem, val);
}

void down(struct semaphore *sem);
int __must_check down_interruptible(struct semaphore *sem);
int __must_check down_killable(struct semaphore *sem);
int __must_check down_trylock(struct semaphore *sem);
int __must_check down_timeout(struct semaphore *sem, long jiffies);
void up(struct semaphore *sem);

#endif /* _LEGO_SEMAPHORE_H_ */
