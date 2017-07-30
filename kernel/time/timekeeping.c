/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/time.h>
#include <lego/timex.h>
#include <lego/ktime.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>
#include <lego/spinlock.h>
#include <lego/timekeeping.h>
#include <lego/clocksource.h>

#include "internal.h"

#define TK_CLEAR_NTP		(1 << 0)
#define TK_MIRROR		(1 << 1)
#define TK_CLOCK_WAS_SET	(1 << 2)

static struct {
	struct timekeeper	timekeeper;
} tk_core ____cacheline_aligned;

static DEFINE_SPINLOCK(timekeeper_lock);

/* Flag for if there is a persistent clock on this platform */
static bool persistent_clock_exists;

/**
 * tk_setup_internals - Set up internals to use clocksource clock.
 *
 * @tk:		The target timekeeper to setup.
 * @clock:	Pointer to clocksource.
 *
 * Calculates a fixed cycle/nsec interval for a given clocksource/adjustment
 * pair and interval request.
 *
 * Unless you're the timekeeping code, you should not be using this!
 */
static void tk_setup_internals(struct timekeeper *tk, struct clocksource *clock)
{
	u64 interval;
	u64 tmp, ntpinterval;
	struct clocksource *old_clock;

	++tk->cs_was_changed_seq;
	old_clock = tk->tkr_mono.clock;
	tk->tkr_mono.clock = clock;
	tk->tkr_mono.read = clock->read;
	tk->tkr_mono.mask = clock->mask;
	tk->tkr_mono.cycle_last = tk->tkr_mono.read(clock);

	tk->tkr_raw.clock = clock;
	tk->tkr_raw.read = clock->read;
	tk->tkr_raw.mask = clock->mask;
	tk->tkr_raw.cycle_last = tk->tkr_mono.cycle_last;

	/* Do the ns -> cycle conversion first, using original mult */
	tmp = NTP_INTERVAL_LENGTH;
	tmp <<= clock->shift;
	ntpinterval = tmp;
	tmp += clock->mult/2;
	do_div(tmp, clock->mult);
	if (tmp == 0)
		tmp = 1;

	interval = (u64) tmp;
	tk->cycle_interval = interval;

	/* Go back from cycles -> shifted ns */
	tk->xtime_interval = interval * clock->mult;
	tk->xtime_remainder = ntpinterval - tk->xtime_interval;
	tk->raw_interval = (interval * clock->mult) >> clock->shift;

	 /* if changing clocks, convert xtime_nsec shift units */
	if (old_clock) {
		int shift_change = clock->shift - old_clock->shift;
		if (shift_change < 0)
			tk->tkr_mono.xtime_nsec >>= -shift_change;
		else
			tk->tkr_mono.xtime_nsec <<= shift_change;
	}
	tk->tkr_raw.xtime_nsec = 0;

	tk->tkr_mono.shift = clock->shift;
	tk->tkr_raw.shift = clock->shift;

	tk->ntp_error = 0;
	tk->ntp_error_shift = NTP_SCALE_SHIFT - clock->shift;
	tk->ntp_tick = ntpinterval << tk->ntp_error_shift;

	/*
	 * The timekeeper keeps its own mult values for the currently
	 * active clocksource. These value will be adjusted via NTP
	 * to counteract clock drifting.
	 */
	tk->tkr_mono.mult = clock->mult;
	tk->tkr_raw.mult = clock->mult;
	tk->ntp_err_mult = 0;
}

static inline struct timespec tk_xtime(struct timekeeper *tk)
{
	struct timespec ts;

	ts.tv_sec = tk->xtime_sec;
	ts.tv_nsec = (long)(tk->tkr_mono.xtime_nsec >> tk->tkr_mono.shift);
	return ts;
}

static void tk_set_xtime(struct timekeeper *tk, const struct timespec *ts)
{
	tk->xtime_sec = ts->tv_sec;
	tk->tkr_mono.xtime_nsec = (u64)ts->tv_nsec << tk->tkr_mono.shift;
}

static void tk_set_wall_to_mono(struct timekeeper *tk, struct timespec wtm)
{
	struct timespec tmp;

	/*
	 * Verify consistency of: offset_real = -wall_to_monotonic
	 * before modifying anything
	 */
	set_normalized_timespec(&tmp, -tk->wall_to_monotonic.tv_sec,
					-tk->wall_to_monotonic.tv_nsec);
	WARN_ON_ONCE(tk->offs_real != timespec_to_ktime(tmp));
	tk->wall_to_monotonic = wtm;
	set_normalized_timespec(&tmp, -wtm.tv_sec, -wtm.tv_nsec);
	tk->offs_real = timespec_to_ktime(tmp);
	tk->offs_tai = ktime_add(tk->offs_real, ktime_set(tk->tai_offset, 0));
}

/* Uses the current clocksource to increment the wall time */
void update_wall_time(void)
{
}

/* must hold timekeeper_lock */
static void timekeeping_update(struct timekeeper *tk, unsigned int action)
{
}

/**
 * timekeeping_notify - Install a new clock source
 * @clock:		pointer to the clock source
 *
 * This function is called from clocksource.c after a new, better clock
 * source has been registered. The caller holds the clocksource_mutex.
 */
int timekeeping_notify(struct clocksource *clock)
{
	return 0;
}

/*
 * timekeeping_init
 * Initializes the clocksource and common timekeeping values
 */
void __init timekeeping_init(void)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	struct clocksource *clock;
	struct timespec now, boot, tmp;
	unsigned long flags;

	read_persistent_clock(&now);

	if (!timespec_valid_strict(&now)) {
		pr_warn("WARNING: Persistent clock returned invalid value!\n"
			"         Check your CMOS/BIOS settings.\n");
		now.tv_sec = 0;
		now.tv_nsec = 0;
	} else if (now.tv_sec || now.tv_nsec)
		persistent_clock_exists = true;

	spin_lock_irqsave(&timekeeper_lock, flags);

	ntp_init();

	/*
	 * We are called before time_init(), so better clocksources
	 * are not even registered. So we use our default jiffies
	 * clocksource first. Later on if time_init() registe better
	 * ones, it will use timekeeping_notify() to tell us:
	 *
	 * Why jiffies can a clocksource? Because jiffies is updated
	 * during every timer interrupt. So it is sort of a software
	 * clocksource, and it has granunality of 1 HZ.
	 *
	 * Of course, timer interrupt is fired by clockevent devices.
	 */
	clock = clocksource_default_clock();
	if (clock->enable)
		clock->enable(clock);

	tk_setup_internals(tk, clock);
	tk_set_xtime(tk, &now);
	tk->raw_time.tv_sec = 0;
	tk->raw_time.tv_nsec = 0;

	boot = tk_xtime(tk);
	set_normalized_timespec(&tmp, -boot.tv_sec, -boot.tv_nsec);
	tk_set_wall_to_mono(tk, tmp);

	timekeeping_update(tk, TK_MIRROR | TK_CLOCK_WAS_SET);

	spin_unlock_irqrestore(&timekeeper_lock, flags);
}

/* TODO */
ktime_t ktime_get(void)
{
	return jiffies;
}

ktime_t ktime_get_with_offset(enum tk_offsets offs)
{
	return jiffies;
}

void do_timer(unsigned long ticks)
{
	jiffies += ticks;
}
