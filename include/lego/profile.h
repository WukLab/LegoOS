/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROFILE_H_
#define _LEGO_PROFILE_H_

#include <lego/sched.h>
#include <lego/profile_point.h>

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

/*
 * heatmap
 * or, /proc/profile
 */

#define CPU_PROFILING	1
#define SCHED_PROFILING	2

#ifdef CONFIG_PROFILING_KERNEL_HEATMAP
extern int prof_on __read_mostly;

int profile_heatmap_init(void);
void print_profile_heatmap_nr(int nr);

/*
 * Add multiple profiler hits to a given address:
 */
void profile_hits(int type, void *ip, unsigned int nr_hits);
void profile_tick(int type);

/*
 * Single profiler hit:
 */
static inline void profile_hit(int type, void *ip)
{
	/*
	 * Speedup for the common (no profiling enabled) case:
	 */
	if (unlikely(prof_on == type))
		profile_hits(type, ip, 1);
}

#else

#define prof_on	0

static inline void print_profile_heatmap_nr(int nr)
{

}

static inline int profile_heatmap_init(void)
{
	return 0;
}

static inline void profile_tick(int type)
{
	return;
}

static inline void profile_hits(int type, void *ip, unsigned int nr_hits)
{
	return;
}

static inline void profile_hit(int type, void *ip)
{
	return;
}

#endif /* CONFIG_PROFILING_KERNEL_HEATMAP */

#endif /* _LEGO_PROFILE_H_ */
