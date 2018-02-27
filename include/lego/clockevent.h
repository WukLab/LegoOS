/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_CLOCKEVENT_H_
#define _LEGO_CLOCKEVENT_H_

#include <lego/ktime.h>
#include <lego/cpumask.h>
#include <lego/clocksource.h>

/*
 * Possible states of a clock event device.
 *
 * DETACHED:	Device is not used by clockevents core. Initial state or can be
 *		reached from SHUTDOWN.
 * SHUTDOWN:	Device is powered-off. Can be reached from PERIODIC or ONESHOT.
 * PERIODIC:	Device is programmed to generate events periodically. Can be
 *		reached from DETACHED or SHUTDOWN.
 * ONESHOT:	Device is programmed to generate event only once. Can be reached
 *		from DETACHED or SHUTDOWN.
 * ONESHOT_STOPPED: Device was programmed in ONESHOT mode and is temporarily
 *		    stopped.
 */
enum clock_event_state {
	CLOCK_EVT_STATE_DETACHED,
	CLOCK_EVT_STATE_SHUTDOWN,
	CLOCK_EVT_STATE_PERIODIC,
	CLOCK_EVT_STATE_ONESHOT,
	CLOCK_EVT_STATE_ONESHOT_STOPPED,
};

/*
 * Clock event features
 */
# define CLOCK_EVT_FEAT_PERIODIC	0x000001
# define CLOCK_EVT_FEAT_ONESHOT		0x000002
# define CLOCK_EVT_FEAT_KTIME		0x000004

/*
 * x86(64) specific (mis)features:
 *
 * - Clockevent source stops in C3 State and needs broadcast support.
 * - Local APIC timer is used as a dummy device.
 */
# define CLOCK_EVT_FEAT_C3STOP		0x000008
# define CLOCK_EVT_FEAT_DUMMY		0x000010

/**
 * struct clock_event_device - clock event device descriptor
 * @event_handler:	Assigned by the framework to be called by the low
 *			level handler of the event source
 * @set_next_event:	set next event function using a clocksource delta
 * @set_next_ktime:	set next event function using a direct ktime value
 * @next_event:		local storage for the next event in oneshot mode
 * @max_delta_ns:	maximum delta value in ns
 * @min_delta_ns:	minimum delta value in ns
 * @mult:		nanosecond to cycles multiplier
 * @shift:		nanoseconds to cycles divisor (power of two)
 * @state_use_accessors:current state of the device, assigned by the core code
 * @features:		features
 * @retries:		number of forced programming retries
 * @set_state_periodic:	switch state to periodic
 * @set_state_oneshot:	switch state to oneshot
 * @set_state_oneshot_stopped: switch state to oneshot_stopped
 * @set_state_shutdown:	switch state to shutdown
 * @tick_resume:	resume clkevt device
 * @broadcast:		function to broadcast events
 * @min_delta_ticks:	minimum delta value in ticks stored for reconfiguration
 * @max_delta_ticks:	maximum delta value in ticks stored for reconfiguration
 * @name:		ptr to clock event name
 * @rating:		variable to rate clock event devices
 * @irq:		IRQ number (only for non CPU local devices)
 * @bound_on:		Bound on CPU
 * @cpumask:		cpumask to indicate for which CPUs this device works
 * @list:		list head for the management code
 */
struct clock_event_device {
	void			(*event_handler)(struct clock_event_device *);
	int			(*set_next_event)(unsigned long evt, struct clock_event_device *);
	int			(*set_next_ktime)(ktime_t expires, struct clock_event_device *);
	ktime_t			next_event;
	u64			max_delta_ns;
	u64			min_delta_ns;
	u32			mult;
	u32			shift;
	enum clock_event_state	state_use_accessors;
	unsigned int		features;
	unsigned long		retries;

	int			(*set_state_periodic)(struct clock_event_device *);
	int			(*set_state_oneshot)(struct clock_event_device *);
	int			(*set_state_oneshot_stopped)(struct clock_event_device *);
	int			(*set_state_shutdown)(struct clock_event_device *);
	int			(*tick_resume)(struct clock_event_device *);

	void			(*broadcast)(const struct cpumask *mask);
	void			(*suspend)(struct clock_event_device *);
	void			(*resume)(struct clock_event_device *);
	unsigned long		min_delta_ticks;
	unsigned long		max_delta_ticks;

	const char		*name;
	int			rating;
	int			irq;
	int			bound_on;
	const struct cpumask	*cpumask;
	struct list_head	list;
} ____cacheline_aligned;

/**
 * tick_handle_periodic
 *
 * Common entry for tick handling.
 * Called from timer interrupt handler.
 */
void tick_handle_periodic(struct clock_event_device *dev);


/**
 * tick_handle_noop
 *
 * Noop handler when we shut down an event device
 */
void tick_handle_noop(struct clock_event_device *dev);

static inline enum clock_event_state clockevent_get_state(struct clock_event_device *dev)
{
	return dev->state_use_accessors;
}

/* Helpers to verify state of a clockevent device */
static inline bool clockevent_state_detached(struct clock_event_device *dev)
{
	return dev->state_use_accessors == CLOCK_EVT_STATE_DETACHED;
}

static inline void clockevent_set_state(struct clock_event_device *dev,
					enum clock_event_state state)
{
	dev->state_use_accessors = state;
}

static inline bool clockevent_state_shutdown(struct clock_event_device *dev)
{
	return dev->state_use_accessors == CLOCK_EVT_STATE_SHUTDOWN;
}

static inline bool clockevent_state_periodic(struct clock_event_device *dev)
{
	return dev->state_use_accessors == CLOCK_EVT_STATE_PERIODIC;
}

static inline bool clockevent_state_oneshot(struct clock_event_device *dev)
{
	return dev->state_use_accessors == CLOCK_EVT_STATE_ONESHOT;
}

static inline bool clockevent_state_oneshot_stopped(struct clock_event_device *dev)
{
	return dev->state_use_accessors == CLOCK_EVT_STATE_ONESHOT_STOPPED;
}

/* Clock event layer functions */
u64 clockevent_delta2ns(unsigned long latch, struct clock_event_device *evt);
void clockevents_register_device(struct clock_event_device *dev);

void clockevents_config_and_register(struct clock_event_device *dev,
				    u32 freq, unsigned long min_delta,
				    unsigned long max_delta);

void clockevents_exchange_device(struct clock_event_device *old,
				 struct clock_event_device *new);

void clockevents_shutdown(struct clock_event_device *dev);

void clockevents_switch_state(struct clock_event_device *dev,
			      enum clock_event_state state);

/*
 * Calculate a multiplication factor for scaled math, which is used to convert
 * nanoseconds based values to clock ticks:
 *
 * clock_ticks = (nanoseconds * factor) >> shift.
 *
 * div_sc is the rearranged equation to calculate a factor from a given clock
 * ticks / nanoseconds ratio:
 *
 * factor = (clock_ticks << shift) / nanoseconds
 */
static inline unsigned long
div_sc(unsigned long ticks, unsigned long nsec, int shift)
{
	u64 tmp = ((u64)ticks) << shift;

	do_div(tmp, nsec);

	return (unsigned long) tmp;
}

#endif /* _LEGO_CLOCKEVENT_H_ */
