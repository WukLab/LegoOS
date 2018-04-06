/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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
#include <lego/timer.h>
#include <lego/kernel.h>
#include <lego/cpumask.h>
#include <lego/irqdesc.h>
#include <lego/percpu.h>
#include <lego/profile.h>
#include <lego/jiffies.h>
#include <lego/clockevent.h>
#include <lego/clocksource.h>
#include <lego/timekeeping.h>
#include <lego/kernel_stat.h>

#include <asm/irq_regs.h>

#include "tick-internal.h"

DEFINE_PER_CPU(struct tick_device, tick_devices);

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

/**
 * tick_check_oneshot_mode - check whether the system is in oneshot mode
 *
 * returns 1 when either nohz or highres are enabled. otherwise 0.
 */
int tick_oneshot_mode_active(void)
{
	unsigned long flags;
	int ret;
	struct tick_device *dev;

	local_irq_save(flags);
	dev = this_cpu_ptr(&tick_devices);
	ret = dev->mode == TICKDEV_MODE_ONESHOT;
	local_irq_restore(flags);

	return ret;
}

static bool tick_check_preferred(struct clock_event_device *curdev,
				 struct clock_event_device *newdev)
{
	/* Prefer oneshot capable device */
	if (!(newdev->features & CLOCK_EVT_FEAT_ONESHOT)) {
		if (curdev && (curdev->features & CLOCK_EVT_FEAT_ONESHOT))
			return false;
		if (tick_oneshot_mode_active())
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

void tick_setup_periodic(struct clock_event_device *dev, int broadcast)
{
	/*
	 * Right on,
	 * set default tick-common periodic handler:
	 */
	dev->event_handler = tick_handle_periodic;

	if (dev->features & CLOCK_EVT_FEAT_PERIODIC) {
		/*
		 * If the device wants to set periodic mode
		 * then call back the device and set it:
		 */
		clockevents_switch_state(dev, CLOCK_EVT_STATE_PERIODIC);
	} else {
		/*
		 * Otherwise, the device wants to set one-shot mode
		 */
		ktime_t next;

		next = tick_next_period;
		clockevents_switch_state(dev, CLOCK_EVT_STATE_ONESHOT);

		for (;;) {
			if (!clockevents_program_event(dev, next, false))
				return;
			next = ktime_add(next, tick_period);
		}
	}
}

/*
 * Setup the tick device
 * Register common tick handler if needed
 */
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
		tick_setup_periodic(newdev, 0);
	} else {
		panic("No support for one-shot mode\n");
		//tick_setup_oneshot(newdev, handler, next_event);
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
	td = &per_cpu(tick_devices, cpu);
	curdev = td->evtdev;

	/* cpu local device ? */
	if (!tick_check_percpu(curdev, newdev, cpu))
		goto out;

	/* Preference decision */
	if (!tick_check_preferred(curdev, newdev))
		goto out;

	/*
	 * Replace the existing device by the new device:
	 */
	clockevents_exchange_device(curdev, newdev);

	/*
	 * Set the timer device to run...
	 * IRQ is all set and interupt is enabld
	 * just enable the device itself:
	 */
	tick_setup_device(td, newdev, cpu, cpumask_of(cpu));

	return;

out:
	pr_debug("Clockevent: %s not installed\n", newdev->name);
}

/*
 * Noop handler when we shut down an event device.
 * It may run several times during intermediate state.
 */
void tick_handle_noop(struct clock_event_device *dev)
{
	pr_info("[%s] jiffies: %lu\n", __func__, jiffies);
}

/**
 * tick_handle_periodic - Event handler for periodic ticks
 *
 * This function is the general interface between clock event
 * device and the clockevent framework.
 *
 * Everytime a timer interrupt fires, the device timer interrupt
 * handler will call back to this function to let kernel handle
 * general timing bookkeeping job.
 *
 * Only one CPU will update the jiffies (Default is CPU0).
 */
void tick_handle_periodic(struct clock_event_device *dev)
{
	int cpu = smp_processor_id();
	int user_tick = user_mode(get_irq_regs());

	/*
	 * Things only one CPU core should do...
	 */
	if (cpu == tick_do_timer_cpu) {
		/* jiffies += 1 */
		do_timer(1);

		/* Keep track of the next tick event */
		tick_next_period = ktime_add(tick_next_period, tick_period);

		update_wall_time();
	}

	/*
	 * Things every CPU core should do...
	 */
	account_process_tick(current, user_tick);
	run_local_timers();
	scheduler_tick();

	/* Oh, sweet profile heatmap */
	profile_tick(CPU_PROFILING);
}
