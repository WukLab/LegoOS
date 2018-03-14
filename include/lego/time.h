/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_TIME_H_
#define _LEGO_TIME_H_

#include <lego/math64.h>
#include <lego/types.h>
#include <lego/string.h>
#include <lego/compiler.h>

/* Parameters used to convert the timespec values: */
#define MSEC_PER_SEC	1000L
#define USEC_PER_MSEC	1000L
#define NSEC_PER_USEC	1000L
#define NSEC_PER_MSEC	1000000L
#define USEC_PER_SEC	1000000L
#define NSEC_PER_SEC	1000000000L
#define FSEC_PER_SEC	1000000000000000LL

struct timespec {
	__kernel_time_t		tv_sec;		/* seconds */
	long			tv_nsec;	/* nanoseconds */
};

struct timeval {
	__kernel_time_t		tv_sec;		/* seconds */
	__kernel_suseconds_t	tv_usec;	/* microseconds */
};

struct timezone {
	int			tz_minuteswest;	/* minutes west of Greenwich */
	int			tz_dsttime;	/* type of dst correction */
};

/*
 * Names of the interval timers,
 * and structure defining a timer setting:
 */
#define	ITIMER_REAL		0
#define	ITIMER_VIRTUAL		1
#define	ITIMER_PROF		2

struct itimerspec {
	struct timespec		it_interval;	/* timer period */
	struct timespec		it_value;	/* timer expiration */
};

struct itimerval {
	struct timeval		it_interval;	/* timer interval */
	struct timeval		it_value;	/* current value */
};

/*
 * The IDs of the various system clocks (for POSIX.1b interval timers):
 */
#define CLOCK_REALTIME			0
#define CLOCK_MONOTONIC			1
#define CLOCK_PROCESS_CPUTIME_ID	2
#define CLOCK_THREAD_CPUTIME_ID		3
#define CLOCK_MONOTONIC_RAW		4
#define CLOCK_REALTIME_COARSE		5
#define CLOCK_MONOTONIC_COARSE		6
#define CLOCK_BOOTTIME			7
#define CLOCK_REALTIME_ALARM		8
#define CLOCK_BOOTTIME_ALARM		9

#define MAX_CLOCKS			16
#define CLOCKS_MASK			(CLOCK_REALTIME | CLOCK_MONOTONIC)
#define CLOCKS_MONO			CLOCK_MONOTONIC

#define TIME_MAX			((s64)~((u64)1 << 63))
#define KTIME_MAX			((s64)~((u64)1 << 63))
#define KTIME_SEC_MAX			(KTIME_MAX / NSEC_PER_SEC)

void __init timekeeping_init(void);
void __init time_init(void);

time_t mktime(const unsigned int year0,
	const unsigned int mon0, const unsigned int day,
	const unsigned int hour, const unsigned int min,
	const unsigned int sec);

void set_normalized_timespec(struct timespec *ts, time_t sec, s64 nsec);
struct timespec ns_to_timespec(const s64 nsec);
struct timeval ns_to_timeval(const s64 nsec);
clock_t jiffies_to_clock_t(unsigned long x);

/*
 * Returns true if the timespec is norm, false if denorm:
 */
static inline bool timespec_valid(const struct timespec *ts)
{
	/* Dates before 1970 are bogus */
	if (ts->tv_sec < 0)
		return false;
	/* Can't have more nanoseconds then a second */
	if ((unsigned long)ts->tv_nsec >= NSEC_PER_SEC)
		return false;
	return true;
}

static inline bool timespec_valid_strict(const struct timespec *ts)
{
	if (!timespec_valid(ts))
		return false;
	/* Disallow values that could overflow ktime_t */
	if ((unsigned long long)ts->tv_sec >= KTIME_SEC_MAX)
		return false;
	return true;
}

static inline bool timeval_valid(const struct timeval *tv)
{
	/* Dates before 1970 are bogus */
	if (tv->tv_sec < 0)
		return false;

	/* Can't have more microseconds then a second */
	if (tv->tv_usec < 0 || tv->tv_usec >= USEC_PER_SEC)
		return false;

	return true;
}

/*
 * sub = lhs - rhs, in normalized form
 */
static inline struct timespec timespec_sub(struct timespec lhs,
						struct timespec rhs)
{
	struct timespec ts_delta;
	set_normalized_timespec(&ts_delta, lhs.tv_sec - rhs.tv_sec,
				lhs.tv_nsec - rhs.tv_nsec);
	return ts_delta;
}

/*
 * Validates if a timespec/timeval used to inject a time offset is valid.
 * Offsets can be postive or negative. The value of the timeval/timespec
 * is the sum of its fields, but *NOTE*: the field tv_usec/tv_nsec must
 * always be non-negative.
 */
static inline bool timeval_inject_offset_valid(const struct timeval *tv)
{
	/* We don't check the tv_sec as it can be positive or negative */

	/* Can't have more microseconds then a second */
	if (tv->tv_usec < 0 || tv->tv_usec >= USEC_PER_SEC)
		return false;
	return true;
}

static inline bool timespec_inject_offset_valid(const struct timespec *ts)
{
	/* We don't check the tv_sec as it can be positive or negative */

	/* Can't have more nanoseconds then a second */
	if (ts->tv_nsec < 0 || ts->tv_nsec >= NSEC_PER_SEC)
		return false;
	return true;
}

#define CURRENT_TIME		(current_kernel_time())
#define CURRENT_TIME_SEC	((struct timespec) { get_seconds(), 0 })

unsigned long get_seconds(void);
struct timespec current_kernel_time(void);

/**
 * timespec_add_ns - Adds nanoseconds to a timespec
 * @a:		pointer to timespec to be incremented
 * @ns:		unsigned nanoseconds value to be added
 *
 * This must always be inlined because its used from the x86-64 vdso,
 * which cannot call other kernel functions.
 */
static __always_inline void timespec_add_ns(struct timespec *a, u64 ns)
{
	a->tv_sec += __iter_div_u64_rem(a->tv_nsec + ns, NSEC_PER_SEC, &ns);
	a->tv_nsec = ns;
}

struct task_struct;
void posix_cpu_timers_exit(struct task_struct *task);
void posix_cpu_timers_exit_group(struct task_struct *task);

#endif /* _LEGO_TIME_H_ */
