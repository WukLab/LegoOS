/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/time.h>
#include <lego/ktime.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>
#include <lego/spinlock.h>
#include <lego/timekeeping.h>
#include <lego/clocksource.h>

static struct {
	struct timekeeper	timekeeper;
} tk_core ____cacheline_aligned;

static DEFINE_SPINLOCK(timekeeper_lock);

/* Flag for if there is a persistent clock on this platform */
static bool persistent_clock_exists;

/*
 * timekeeping_init
 * Initializes the clocksource and common timekeeping values
 */
void __init timekeeping_init(void)
{
	struct timekeeper *tk = &tk_core.timekeeper;
	struct clocksource *clock;
	struct timespec now, tmp;

	read_persistent_clock(&now);

	if (!timespec_valid_strict(&now)) {
		pr_warn("WARNING: Persistent clock returned invalid value!\n"
			"         Check your CMOS/BIOS settings.\n");
		now.tv_sec = 0;
		now.tv_nsec = 0;
	} else if (now.tv_sec || now.tv_nsec)
		persistent_clock_exists = true;

	clock = clocksource_default_clock();
	if (clock->enable)
		clock->enable(clock);
}
