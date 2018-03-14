/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 *  ktime_t - nanosecond-resolution time format.
 */

#ifndef _LEGO_KTIME_H_
#define _LEGO_KTIME_H_

#include <lego/time.h>

/* Nanosecond scalar representation for kernel time values */
typedef s64	ktime_t;

/* Map the ktime_t to timespec conversion to ns_to_timespec function */
#define ktime_to_timespec(kt)		ns_to_timespec((kt))

/* Map the ktime_t to timeval conversion to ns_to_timeval function */
#define ktime_to_timeval(kt)		ns_to_timeval((kt))

/**
 * ktime_set - Set a ktime_t variable from a seconds/nanoseconds value
 * @secs:	seconds to set
 * @nsecs:	nanoseconds to set
 *
 * Return: The ktime_t representation of the value.
 */
static inline ktime_t ktime_set(const s64 secs, const unsigned long nsecs)
{
	if (unlikely(secs >= KTIME_SEC_MAX))
		return KTIME_MAX;

	return secs * NSEC_PER_SEC + (s64)nsecs;
}

/* Subtract two ktime_t variables. rem = lhs -rhs: */
#define ktime_sub(lhs, rhs)	((lhs) - (rhs))

/* Add two ktime_t variables. res = lhs + rhs: */
#define ktime_add(lhs, rhs)	((lhs) + (rhs))

/*
 * Same as ktime_add(), but avoids undefined behaviour on overflow; however,
 * this means that you must check the result for overflow yourself.
 */
#define ktime_add_unsafe(lhs, rhs)	((u64) (lhs) + (rhs))

/*
 * Add a ktime_t variable and a scalar nanosecond value.
 * res = kt + nsval:
 */
#define ktime_add_ns(kt, nsval)		((kt) + (nsval))

/*
 * Subtract a scalar nanosecod from a ktime_t variable
 * res = kt - nsval:
 */
#define ktime_sub_ns(kt, nsval)		((kt) - (nsval))

/* Convert ktime_t to nanoseconds - NOP in the scalar storage format: */
#define ktime_to_ns(kt)			(kt)

/* Convert ktime_t to microseconds - NOP in the scalar storage format: */
#define ktime_to_ms(kt)			(kt/NSEC_PER_MSEC)

static inline ktime_t ktime_add_us(const ktime_t kt, const u64 usec)
{
	return ktime_add_ns(kt, usec * NSEC_PER_USEC);
}

static inline ktime_t ktime_add_ms(const ktime_t kt, const u64 msec)
{
	return ktime_add_ns(kt, msec * NSEC_PER_MSEC);
}

static inline ktime_t ktime_sub_us(const ktime_t kt, const u64 usec)
{
	return ktime_sub_ns(kt, usec * NSEC_PER_USEC);
}

static inline ktime_t ktime_sub_ms(const ktime_t kt, const u64 msec)
{
	return ktime_sub_ns(kt, msec * NSEC_PER_MSEC);
}

/* convert a timespec to ktime_t format: */
static inline ktime_t timespec_to_ktime(struct timespec ts)
{
	return ktime_set(ts.tv_sec, ts.tv_nsec);
}

/* convert a timeval to ktime_t format: */
static inline ktime_t timeval_to_ktime(struct timeval tv)
{
	return ktime_set(tv.tv_sec, tv.tv_usec * NSEC_PER_USEC);
}

static inline ktime_t ns_to_ktime(u64 ns)
{
	static const ktime_t ktime_zero = 0;

	return ktime_add_ns(ktime_zero, ns);
}

static inline ktime_t ms_to_ktime(u64 ms)
{
	static const ktime_t ktime_zero = 0;

	return ktime_add_ms(ktime_zero, ms);
}

extern ktime_t ktime_get(void);

#endif /* _LEGO_KTIME_H_ */
