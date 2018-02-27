/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_TIMX_H_
#define _LEGO_TIMX_H_

/* The clock frequency of the i8253/i8254 PIT */
#define PIT_TICK_RATE		1193182ul

/* Assume we use the PIT time source for the clock tick */
#define CLOCK_TICK_RATE		PIT_TICK_RATE

#endif /* _LEGO_TIMX_H_ */
