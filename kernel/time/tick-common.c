/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/bug.h>
#include <lego/irq.h>
#include <lego/smp.h>
#include <lego/time.h>
#include <lego/kernel.h>
#include <lego/cpumask.h>
#include <lego/irqdesc.h>
#include <lego/jiffies.h>
#include <lego/clockevent.h>
#include <lego/clocksource.h>

#include "tick-internal.h"

/* TODO: per-cpu */
struct tick_device tick_devices[NR_CPUS];

struct tick_device *get_tick_device(void)
{
	int cpu = smp_processor_id();

	BUG_ON(!cpu_online(cpu));
	return &tick_devices[cpu];
}

void set_tick_device(struct tick_device *dev)
{
	int cpu = smp_processor_id();

	BUG_ON(!cpu_online(cpu));
	tick_devices[cpu] = *dev;
}

/*
 * Tick next event: keeps track of the tick time
 */
ktime_t tick_next_period;
ktime_t tick_period;

/*
 * tick_do_timer_cpu is a timer core internal variable which holds the CPU NR
 * which is responsible for calling do_timer(), i.e. the timekeeping stuff. This
 * variable has two functions:
 *
 * 1) Prevent a thundering herd issue of a gazillion of CPUs trying to grab the
 *    timekeeping lock all at once. Only the CPU which is assigned to do the
 *    update is handling it.
 *
 * 2) Hand off the duty in the NOHZ idle case by setting the value to
 *    TICK_DO_TIMER_NONE, i.e. a non existing CPU. So the next cpu which looks
 *    at it will take over and keep the time keeping alive.  The handover
 *    procedure also covers cpu hotplug.
 */
#define TICK_DO_TIMER_NONE	-1
#define TICK_DO_TIMER_BOOT	-2
int tick_do_timer_cpu __read_mostly = TICK_DO_TIMER_BOOT;

static bool tick_check_percpu(struct clock_event_device *curdev,
			      struct clock_event_device *newdev, int cpu)
{
	if (!cpumask_test_cpu(cpu, newdev->cpumask))
		return false;
	if (cpumask_equal(newdev->cpumask, cpumask_of(cpu)))
		return true;
	/* Check if irq affinity can be set */
	if (newdev->irq >= 0 && !irq_can_set_affinity(newdev->irq))
		return false;
	/* Prefer an existing cpu local device */
	if (curdev && cpumask_equal(curdev->cpumask, cpumask_of(cpu)))
		return false;
	return true;
}

static bool tick_check_preferred(struct clock_event_device *curdev,
				 struct clock_event_device *newdev)
{
	/* Prefer oneshot capable device */
	if (!(newdev->features & CLOCK_EVT_FEAT_ONESHOT)) {
		if (curdev && (curdev->features & CLOCK_EVT_FEAT_ONESHOT))
			return false;
	}

	/*
	 * Use the higher rated one, but prefer a CPU local device with a lower
	 * rating than a non-CPU local device
	 */
	return !curdev ||
		newdev->rating > curdev->rating ||
	       !cpumask_equal(curdev->cpumask, newdev->cpumask);
}

static void tick_setup_device(struct tick_device *td,
			      struct clock_event_device *newdev, int cpu,
			      const struct cpumask *cpumask)
{
	void (*handler)(struct clock_event_device *) = NULL;
	ktime_t next_event = 0;

	/*
	 * First time to setup device?
	 */
	if (!td->evtdev) {
		/*
		 * If no cpu took the do_timer update, assign it to
		 * this cpu:
		 */
		if (tick_do_timer_cpu == TICK_DO_TIMER_BOOT) {
			tick_do_timer_cpu = cpu;
			tick_next_period = ktime_get();
			tick_period = NSEC_PER_SEC / HZ;
		}

		/*
		 * Startup in periodic mode first.
		 */
		td->mode = TICKDEV_MODE_PERIODIC;
	} else {
		handler = td->evtdev->event_handler;
		next_event = td->evtdev->next_event;
		td->evtdev->event_handler = tick_handle_noop;
	}

	td->evtdev = newdev;

	/*
	 * When the device is not per cpu, pin the interrupt to the
	 * current cpu:
	 */
	if (!cpumask_equal(newdev->cpumask, cpumask))
		irq_set_affinity(newdev->irq, cpumask);

	if (td->mode == TICKDEV_MODE_PERIODIC) {
		clockevents_switch_state(newdev, CLOCK_EVT_STATE_PERIODIC);
	} else {
		WARN(1, "no one-shot support now");
	}
}

/*
 * Check, if the new registered device should be used.
 * Called with clockevents_lock held and interrupts disabled.
 */
void tick_check_new_device(struct clock_event_device *newdev)
{
	struct clock_event_device *curdev;
	struct tick_device *td;
	int cpu;

	cpu = smp_processor_id();
	td = get_tick_device();
	curdev = td->evtdev;

	/* cpu local device ? */
	if (!tick_check_percpu(curdev, newdev, cpu))
		goto out;

	/* Preference decision */
	if (!tick_check_preferred(curdev, newdev))
		goto out;

	clockevents_exchange_device(curdev, newdev);

	/*
	 * Set the timer device to run...
	 */
	tick_setup_device(td, newdev, cpu, cpumask_of(cpu));

#if 0
	if (newdev->features & CLOCK_EVT_FEAT_ONESHOT)
		tick_oneshot_notify();
#endif
	return;

out:
	pr_debug("Clockevent: %s not installed\n", newdev->name);
}

/*
 * Noop handler when we shut down an event device
 */
void tick_handle_noop(struct clock_event_device *dev)
{
}

/*
 * Event handler for periodic ticks
 */
void tick_handle_periodic(struct clock_event_device *dev)
{
	pr_info("%s %pS\n",__func__, dev);
}