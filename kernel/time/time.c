/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/time.h>
#include <lego/timekeeping.h>
#include <lego/uaccess.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>
#include <lego/syscalls.h>

/**
 * mktime - Converts date to seconds.
 * Converts Gregorian date to seconds since 1970-01-01 00:00:00.
 * Assumes input in normal date format, i.e. 1980-12-31 23:59:59
 * => year=1980, mon=12, day=31, hour=23, min=59, sec=59.
 *
 * [For the Julian calendar (which was used in Russia before 1917,
 * Britain & colonies before 1752, anywhere else before 1582,
 * and is still in use by some communities) leave out the
 * -year/100+year/400 terms, and add 10.]
 *
 * This algorithm was first published by Gauss (I think).
 *
 * A leap second can be indicated by calling this function with sec as
 * 60 (allowable under ISO 8601).  The leap second is treated the same
 * as the following second since they don't exist in UNIX time.
 *
 * An encoding of midnight at the end of the day as 24:00:00 - ie. midnight
 * tomorrow - (allowable under ISO 8601) is supported.
 */
time_t mktime(const unsigned int year0, const unsigned int mon0,
	    const unsigned int day, const unsigned int hour,
	    const unsigned int min, const unsigned int sec)
{
	unsigned int mon = mon0, year = year0;

	/* 1..12 -> 11,12,1..10 */
	if (0 >= (int) (mon -= 2)) {
		mon += 12;	/* Puts Feb last since it has leap day */
		year -= 1;
	}

	return ((((time_t)
		  (year/4 - year/100 + year/400 + 367*mon/12 + day) +
		  year*365 - 719499
	    )*24 + hour /* now have hours - midnight tomorrow handled here */
	  )*60 + min /* now have minutes */
	)*60 + sec; /* finally seconds */
}

/**
 * set_normalized_timespec - set timespec sec and nsec parts and normalize
 *
 * @ts:		pointer to timespec variable to be set
 * @sec:	seconds to set
 * @nsec:	nanoseconds to set
 *
 * Set seconds and nanoseconds field of a timespec variable and
 * normalize to the timespec storage format
 *
 * Note: The tv_nsec part is always in the range of
 *	0 <= tv_nsec < NSEC_PER_SEC
 * For negative values only the tv_sec field is negative !
 */
void set_normalized_timespec(struct timespec *ts, time_t sec, s64 nsec)
{
	while (nsec >= NSEC_PER_SEC) {
		/*
		 * The following asm() prevents the compiler from
		 * optimising this loop into a modulo operation. See
		 * also __iter_div_u64_rem() in include/linux/time.h
		 */
		asm("" : "+rm"(nsec));
		nsec -= NSEC_PER_SEC;
		++sec;
	}
	while (nsec < 0) {
		asm("" : "+rm"(nsec));
		nsec += NSEC_PER_SEC;
		--sec;
	}
	ts->tv_sec = sec;
	ts->tv_nsec = nsec;
}

/*
 * Convert jiffies/jiffies_64 to clock_t and back.
 */
clock_t jiffies_to_clock_t(unsigned long x)
{
#if (TICK_NSEC % (NSEC_PER_SEC / USER_HZ)) == 0
# if HZ < USER_HZ
	return x * (USER_HZ / HZ);
# else
	return x / (HZ / USER_HZ);
# endif
#else
	return div_u64((u64)x * TICK_NSEC, NSEC_PER_SEC / USER_HZ);
#endif
}

/*
 * When we convert to jiffies then we interpret incoming values
 * the following way:
 *
 * - negative values mean 'infinite timeout' (MAX_JIFFY_OFFSET)
 *
 * - 'too large' values [that would result in larger than
 *   MAX_JIFFY_OFFSET values] mean 'infinite timeout' too.
 *
 * - all other values are converted to jiffies by either multiplying
 *   the input value by a factor or dividing it with a factor
 *
 * We must also be careful about 32-bit overflows.
 */
unsigned long msecs_to_jiffies(const unsigned int m)
{
	/*
	 * Negative value, means infinite timeout:
	 */
	if ((int)m < 0)
		return MAX_JIFFY_OFFSET;

#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
	/*
	 * HZ is equal to or smaller than 1000, and 1000 is a nice
	 * round multiple of HZ, divide with the factor between them,
	 * but round upwards:
	 */
	return (m + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ);
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
	/*
	 * HZ is larger than 1000, and HZ is a nice round multiple of
	 * 1000 - simply multiply with the factor between them.
	 *
	 * But first make sure the multiplication result cannot
	 * overflow:
	 */
	if (m > jiffies_to_msecs(MAX_JIFFY_OFFSET))
		return MAX_JIFFY_OFFSET;

	return m * (HZ / MSEC_PER_SEC);
#else
	/*
	 * Generic case - multiply, round and divide. But first
	 * check that if we are doing a net multiplication, that
	 * we wouldn't overflow:
	 */
	if (HZ > MSEC_PER_SEC && m > jiffies_to_msecs(MAX_JIFFY_OFFSET))
		return MAX_JIFFY_OFFSET;

	return (MSEC_TO_HZ_MUL32 * m + MSEC_TO_HZ_ADJ32)
		>> MSEC_TO_HZ_SHR32;
#endif
}

/*
 * Convert jiffies to milliseconds and back.
 *
 * Avoid unnecessary multiplications/divisions in the
 * two most common HZ cases:
 */
unsigned int jiffies_to_msecs(const unsigned long j)
{
#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
	return (MSEC_PER_SEC / HZ) * j;
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
	return (j + (HZ / MSEC_PER_SEC) - 1)/(HZ / MSEC_PER_SEC);
#else
# if BITS_PER_LONG == 32
	return (HZ_TO_MSEC_MUL32 * j) >> HZ_TO_MSEC_SHR32;
# else
	return (j * HZ_TO_MSEC_NUM) / HZ_TO_MSEC_DEN;
# endif
#endif
}

unsigned int jiffies_to_usecs(const unsigned long j)
{
	/*
	 * Hz usually doesn't go much further MSEC_PER_SEC.
	 * jiffies_to_usecs() and usecs_to_jiffies() depend on that.
	 */
	BUILD_BUG_ON(HZ > USEC_PER_SEC);

#if !(USEC_PER_SEC % HZ)
	return (USEC_PER_SEC / HZ) * j;
#else
# if BITS_PER_LONG == 32
	return (HZ_TO_USEC_MUL32 * j) >> HZ_TO_USEC_SHR32;
# else
	return (j * HZ_TO_USEC_NUM) / HZ_TO_USEC_DEN;
# endif
#endif
}

/**
 * ns_to_timespec - Convert nanoseconds to timespec
 * @nsec:       the nanoseconds value to be converted
 *
 * Returns the timespec representation of the nsec parameter.
 */
struct timespec ns_to_timespec(const s64 nsec)
{
	struct timespec ts;
	s32 rem;

	if (!nsec)
		return (struct timespec) {0, 0};

	ts.tv_sec = div_s64_rem(nsec, NSEC_PER_SEC, &rem);
	if (unlikely(rem < 0)) {
		ts.tv_sec--;
		rem += NSEC_PER_SEC;
	}
	ts.tv_nsec = rem;

	return ts;
}

SYSCALL_DEFINE1(time, time_t __user *, tloc)
{
	time_t i = get_seconds();

	syscall_enter();
	pr_info("%s(): get_seconds(): %lld\n", __func__, (s64)i);
	if (tloc)
		if (copy_to_user(tloc, &i, sizeof(time_t)))
			return -EFAULT;
	return i;
}

/**
 * do_gettimeofday - Returns the time of day in a timeval
 * @tv:		pointer to the timeval to be set
 *
 * NOTE: Users should be converted to using getnstimeofday()
 */
void do_gettimeofday(struct timeval *tv)
{
	struct timespec now;

	__do_gettimeofday(&now);
	tv->tv_sec = now.tv_sec;
	tv->tv_usec = now.tv_nsec/1000;
}

/*
 * The timezone where the local system is located.  Used as a default by some
 * programs who obtain this value by using gettimeofday.
 */
struct timezone sys_tz;

SYSCALL_DEFINE2(gettimeofday, struct timeval __user *, tv,
		struct timezone __user *, tz)
{
	syscall_enter();
	if (likely(tv != NULL)) {
		struct timeval ktv;
		do_gettimeofday(&ktv);
		if (copy_to_user(tv, &ktv, sizeof(ktv)))
			return -EFAULT;
	}
	if (unlikely(tz != NULL)) {
		if (copy_to_user(tz, &sys_tz, sizeof(sys_tz)))
			return -EFAULT;
	}
	return 0;
}
