/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROFILE_H_
#define _LEGO_PROFILE_H_

#include <lego/sched.h>

/*
 * Idea about this Lego profiling: it should consist of two parts
 * 	1) boot-time profiling
 *	2) runtime profiling
 *
 * Boot-time profiling is more low-level, get a sense about how the underlying
 * hardware perform, e.g. tlb flush latency and context switch latency.
 * This process is invoked during late boot in start_kernel().
 *
 * Runtime profiling is more useful for large chunk of code. For example,
 * to profile a pcache miss latency, network latency etc.
 *
 * Profiling will also need printing. So, when you are adding profile code,
 * be careful not to do it recursively.
 *
 * Also, use the profile_clock() to get the current time in nanosecond.
 */

/* Profiler clock: returns current time in nanosec units */
static inline unsigned long long profile_clock(void)
{
	return sched_clock();
}

/* Arch-specific */
void profile_tlb_shootdown(void);

#ifdef CONFIG_PROFILING_BOOT
void boot_time_profile(void);
#else
static inline void boot_time_profile(void) { }
#endif

#endif /* _LEGO_PROFILE_H_ */
