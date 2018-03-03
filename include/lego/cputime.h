/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_CPUTIME_H_
#define _LEGO_CPUTIME_H_

typedef unsigned long cputime_t;

#define cmpxchg_cputime(ptr, old, new) cmpxchg(ptr, old, new)

#define cputime_one_jiffy		jiffies_to_cputime(1)
#define cputime_to_jiffies(__ct)	(unsigned long)(__ct)
#define cputime_to_scaled(__ct)		(__ct)
#define jiffies_to_cputime(__hz)	(cputime_t)(__hz)

/*
 * Convert nanoseconds <-> cputime
 */
#define cputime_to_nsecs(__ct)		\
	jiffies_to_nsecs(cputime_to_jiffies(__ct))
#define nsecs_to_cputime(__nsec)	\
	jiffies_to_cputime(nsecs_to_jiffies(__nsec))

/*
 * Convert cputime to microseconds and back.
 */
#define cputime_to_usecs(__ct)		\
	jiffies_to_usecs(cputime_to_jiffies(__ct))
#define usecs_to_cputime(__usec)	\
	jiffies_to_cputime(usecs_to_jiffies(__usec))

/*
 * Convert cputime to seconds and back.
 */
#define cputime_to_secs(jif)		(cputime_to_jiffies(jif) / HZ)
#define secs_to_cputime(sec)		jiffies_to_cputime((sec) * HZ)

/*
 * Convert cputime to timespec and back.
 */
#define timespec_to_cputime(__val)	\
	jiffies_to_cputime(timespec_to_jiffies(__val))
#define cputime_to_timespec(__ct,__val)	\
	jiffies_to_timespec(cputime_to_jiffies(__ct),__val)

/*
 * Convert cputime to timeval and back.
 */
#define timeval_to_cputime(__val)	\
	jiffies_to_cputime(timeval_to_jiffies(__val))
#define cputime_to_timeval(__ct,__val)	\
	jiffies_to_timeval(cputime_to_jiffies(__ct),__val)

/*
 * Convert cputime to clock and back.
 */
#define cputime_to_clock_t(__ct)	\
	jiffies_to_clock_t(cputime_to_jiffies(__ct))
#define clock_t_to_cputime(__x)		\
	jiffies_to_cputime(clock_t_to_jiffies(__x))

struct timeval;
void jiffies_to_timeval(const unsigned long jiffies, struct timeval *value);

#endif /* _LEGO_CPUTIME_H_ */
