/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_TIME_H_
#define _ASM_X86_TIME_H_

extern void __init setup_pit_timer(void);

extern struct clock_event_device *global_clock_event;

#endif /* _ASM_X86_TIME_H_ */
