/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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
	/*
	 * All fields that change during normal runtime grouped to the
	 * same cacheline
	 */
	struct hlist_node	entry;
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

void __init_timer(struct timer_list *timer, unsigned int flags);

#define init_timer(timer)			__init_timer((timer), 0)
#define init_timer_pinned(timer)		__init_timer((timer), TIMER_PINNED)
#define init_timer_deferrable(timer)		__init_timer((timer), TIMER_DEFERRABLE)
#define init_timer_pinned_deferrable(timer)	__init_timer((timer), TIMER_DEFERRABLE | TIMER_PINNED)

#define __setup_timer(_timer, _fn, _data, _flags)			\
	do {								\
		__init_timer((_timer), (_flags));			\
		(_timer)->function = (_fn);				\
		(_timer)->data = (_data);				\
	} while (0)

#define setup_timer(timer, fn, data)					\
	__setup_timer((timer), (fn), (data), 0)
#define setup_pinned_timer(timer, fn, data)				\
	__setup_timer((timer), (fn), (data), TIMER_PINNED)
#define setup_deferrable_timer(timer, fn, data)				\
	__setup_timer((timer), (fn), (data), TIMER_DEFERRABLE)
#define setup_pinned_deferrable_timer(timer, fn, data)			\
	__setup_timer((timer), (fn), (data), TIMER_DEFERRABLE | TIMER_PINNED)

/**
 * timer_pending - is a timer pending?
 * @timer: the timer in question
 *
 * timer_pending will tell whether a given timer is currently pending,
 * or not. Callers must ensure serialization wrt. other operations done
 * to this timer, eg. interrupt contexts, or other CPUs on SMP.
 *
 * return value: 1 if the timer is pending, 0 if not.
 */
static inline int timer_pending(const struct timer_list * timer)
{
	return timer->entry.pprev != NULL;
}

unsigned long __round_jiffies(unsigned long j, int cpu);
unsigned long round_jiffies(unsigned long j);
unsigned long __round_jiffies_relative(unsigned long j, int cpu);
unsigned long round_jiffies_relative(unsigned long j);
unsigned long __round_jiffies_up_relative(unsigned long j, int cpu);
unsigned long round_jiffies_up(unsigned long j);
unsigned long round_jiffies_up_relative(unsigned long j);

int mod_timer_pending(struct timer_list *timer, unsigned long expires);
int mod_timer(struct timer_list *timer, unsigned long expires);
void add_timer(struct timer_list *timer);
void add_timer_on(struct timer_list *timer, int cpu);
int del_timer(struct timer_list *timer);
int try_to_del_timer_sync(struct timer_list *timer);

#ifdef CONFIG_SMP
int del_timer_sync(struct timer_list *timer);
#else
#define del_timer_sync(t)	del_timer(t)
#endif

void run_local_timers(void);

void __init init_timers(void);
void msleep(unsigned int msecs);
unsigned long msleep_interruptible(unsigned int msecs);

void it_real_fn(unsigned long __data);

#endif /* _LEGO_TIMER_H_ */
