/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROFILE_FUNC_H_
#define _LEGO_PROFILE_FUNC_H_

#include <lego/kernel.h>
#include <lego/atomic.h>
#include <lego/stringify.h>

struct profile_point {
	bool		enabled;
	char		pp_name[64];
	atomic_long_t	nr;
	atomic_long_t	time_ns;
} ____cacheline_aligned;

#define __profile_point		__section(.profile.point)

#ifdef CONFIG_PROFILING_POINTS

#define _PP_TIME(name)	__profilepoint_start_ns_##name
#define _PP_NAME(name)	__profilepoint_##name

/*
 * Define a profile point
 * It is ON by default.
 */
#define DEFINE_PROFILE_POINT(name)							\
	struct profile_point _PP_NAME(name) __profile_point = {				\
		.enabled	=	true,						\
		.pp_name	=	__stringify(name),				\
	};

/*
 * This is just a solution if per-cpu is not used.
 * Stack is per-thread, thus SMP safe.
 */
#define PROFILE_POINT_TIME(name)							\
	unsigned long _PP_TIME(name) __maybe_unused;

#define profile_point_start(name)							\
	do {										\
		if (_PP_NAME(name).enabled)						\
			_PP_TIME(name) = sched_clock();					\
	} while (0)

#define profile_point_leave(name)							\
	do {										\
		if (_PP_NAME(name).enabled) {						\
			unsigned long __PP_end_time;					\
			unsigned long __PP_diff_time;					\
			__PP_end_time = sched_clock();					\
			__PP_diff_time = __PP_end_time - _PP_TIME(name);		\
			atomic_long_inc(&(_PP_NAME(name).nr));				\
			atomic_long_add(__PP_diff_time, &(_PP_NAME(name).time_ns));	\
		}									\
	} while (0)

#define PROFILE_START(name)								\
	do {										\
		_PP_TIME(name) = sched_clock();						\
	} while (0)

#define PROFILE_LEAVE(name)								\
	do {										\
		unsigned long __PP_end_time;						\
		unsigned long __PP_diff_time;						\
		__PP_end_time = sched_clock();						\
		__PP_diff_time = __PP_end_time - _PP_TIME(name);			\
		atomic_long_inc(&(_PP_NAME(name).nr));					\
		atomic_long_add(__PP_diff_time, &(_PP_NAME(name).time_ns));		\
	} while (0)

void print_profile_point(struct profile_point *pp);
void print_profile_points(void);

#else

#define DEFINE_PROFILE_POINT(name)
#define PROFILE_POINT_TIME(name)
#define profile_point_start(name)	do { } while (0)
#define profile_point_leave(name)	do { } while (0)
#define PROFILE_START(name)		do { } while (0)
#define PROFILE_LEAVE(name)		do { } while (0)

static inline void print_profile_point(struct profile_point *pp) { }
static inline void print_profile_points(void) { }
#endif

#endif /* _LEGO_PROFILE_FUNC_H_ */
