/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _TICK_INTERNAL_H_
#define _TICK_INTERNAL_H_

enum tick_device_mode {
	TICKDEV_MODE_PERIODIC,
	TICKDEV_MODE_ONESHOT,
};

struct tick_device {
	struct clock_event_device *evtdev;
	enum tick_device_mode mode;
};

void tick_check_new_device(struct clock_event_device *newdev);

/* Check, if the device is functional or a dummy for broadcast */
static inline int tick_device_is_functional(struct clock_event_device *dev)
{
	return !(dev->features & CLOCK_EVT_FEAT_DUMMY);
}

int clockevents_program_event(struct clock_event_device *dev, ktime_t expires,
			      bool force);

#endif /* _TICK_INTERNAL_H_ */
