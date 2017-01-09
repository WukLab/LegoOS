/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/irq.h>
#include <lego/irqdesc.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>
#include <lego/clockevent.h>

/*
 * HPET replaces the PIT, when enabled. So we need to know, which of
 * the two timers is used
 */
struct clock_event_device *global_clock_event;

static struct clock_event_device i8253_clockevent;

void __init setup_pit_timer(void)
{
	panic("No i8253 PIT support now\n");
	global_clock_event = &i8253_clockevent;
}
