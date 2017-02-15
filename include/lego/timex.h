/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_TIMEX_H_
#define _LEGO_TIMEX_H_

#include <lego/time.h>

/* Required to safely shift negative values */
#define shift_right(x, s) ({	\
	__typeof__(x) __x = (x);	\
	__typeof__(s) __s = (s);	\
	__x < 0 ? -(-__x >> __s) : __x >> __s;	\
})

#define NTP_SCALE_SHIFT		32

#define NTP_INTERVAL_FREQ	(HZ)
#define NTP_INTERVAL_LENGTH	(NSEC_PER_SEC/NTP_INTERVAL_FREQ)

#endif /* _LEGO_TIMEX_H_ */
