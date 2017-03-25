/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_TIMER_H_
#define _LEGO_TIMER_H_

#include <lego/list.h>
#include <lego/kernel.h>

struct timer_list {
	struct list_head	entry;
	unsigned long		expires;
	void			(*function)(unsigned long);
	unsigned long		data;
	u32			flags;
};

/*
 * A deferrable timer will work normally when the system is busy, but
 * will not cause a CPU to come out of idle just to service it; instead,
 * the timer will be serviced when the CPU eventually wakes up with a
 * subsequent non-deferrable timer.
 *
 * An irqsafe timer is executed with IRQ disabled and it's safe to wait for
 * the completion of the running instance from IRQ handlers, for example,
 * by calling del_timer_sync().
 *
 * Note: The irq disabled callback execution is a special case for
 * workqueue locking issues. It's not meant for executing random crap
 * with interrupts disabled. Abuse is monitored!
 */
#define TIMER_CPUMASK		0x0003FFFF
#define TIMER_MIGRATING		0x00040000
#define TIMER_BASEMASK		(TIMER_CPUMASK | TIMER_MIGRATING)
#define TIMER_DEFERRABLE	0x00080000
#define TIMER_PINNED		0x00100000
#define TIMER_IRQSAFE		0x00200000
#define TIMER_ARRAYSHIFT	22
#define TIMER_ARRAYMASK		0xFFC00000

#define TIMER_TRACE_FLAGMASK	(TIMER_MIGRATING | TIMER_DEFERRABLE | TIMER_PINNED | TIMER_IRQSAFE)

#define __TIMER_INITIALIZER(_name, _function, _expires, _data, _flags) {	\
		.entry		= { &((_name).entry), &((_name).entry) },	\
		.function	= (_function),					\
		.expires	= (_expires),					\
		.data		= (_data),					\
		.flags		= (_flags),					\
	}

#define TIMER_INITIALIZER(_name, _function, _expires, _data)			\
	__TIMER_INITIALIZER((_name), (_function), (_expires), (_data), 0)

#define TIMER_PINNED_INITIALIZER(_name, _function, _expires, _data)		\
	__TIMER_INITIALIZER((_name), (_function), (_expires), (_data), TIMER_PINNED)

#define TIMER_DEFERRED_INITIALIZER(_name, _function, _expires, _data)		\
	__TIMER_INITIALIZER((_name), (_function), (_expires), (_data), TIMER_DEFERRABLE)

#define TIMER_PINNED_DEFERRED_INITIALIZER(_name, _function, _expires, _data)	\
	__TIMER_INITIALIZER((_name), (_function), (_expires), (_data), TIMER_DEFERRABLE | TIMER_PINNED)

#define DEFINE_TIMER(_name, _function, _expires, _data)				\
	struct timer_list _name =						\
		TIMER_INITIALIZER(_name, _function, _expires, _data)

#endif /* _LEGO_TIMER_H_ */
