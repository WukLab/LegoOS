/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_CLOCKSOURCE_H_
#define _LEGO_CLOCKSOURCE_H_

#include <lego/types.h>

/**
 * struct clocksource - hardware abstraction for a free running counter
 *	Provides mostly state-free accessors to the underlying hardware.
 *	This is the structure used for system time.
 *
 * @name:		ptr to clocksource name
 * @list:		list head for registration
 * @rating:		rating value for selection (higher is better)
 *			To avoid rating inflation the following
 *			list should give you a guide as to how
 *			to assign your clocksource a rating
 *			1-99: Unfit for real use
 *				Only available for bootup and testing purposes.
 *			100-199: Base level usability.
 *				Functional for real use, but not desired.
 *			200-299: Good.
 *				A correct and usable clocksource.
 *			300-399: Desired.
 *				A reasonably fast and accurate clocksource.
 *			400-499: Perfect
 *				The ideal clocksource. A must-use where
 *				available.
 * @read:		returns a cycle value, passes clocksource as argument
 * @enable:		optional function to enable the clocksource
 * @disable:		optional function to disable the clocksource
 * @mask:		bitmask for two's complement
 *			subtraction of non 64 bit counters
 * @mult:		cycle to nanosecond multiplier
 * @shift:		cycle to nanosecond divisor (power of two)
 * @max_idle_ns:	max idle time permitted by the clocksource (nsecs)
 * @maxadj:		maximum adjustment value to mult (~11%)
 * @max_cycles:		maximum safe cycle value which won't overflow on multiplication
 * @flags:		flags describing special properties
 * @archdata:		arch-specific data
 * @suspend:		suspend function for the clocksource, if necessary
 * @resume:		resume function for the clocksource, if necessary
 * @owner:		module reference, must be set by clocksource in modules
 *
 * Note: This struct is not used in hotpathes of the timekeeping code
 * because the timekeeper caches the hot path fields in its own data
 * structure, so no line cache alignment is required,
 *
 * The pointer to the clocksource itself is handed to the read
 * callback. If you need extra information there you can wrap struct
 * clocksource into your own struct. Depending on the amount of
 * information you need you should consider to cache line align that
 * structure.
 */
struct clocksource {
	const char *name;
	struct list_head list;
	int rating;
	unsigned long flags;

	cycle_t (*read)(struct clocksource *cs);
	cycle_t mask;
	u64 max_idle_ns;
	u64 max_cycles;
	u32 mult;
	u32 shift;
	u32 maxadj;

	int (*enable)(struct clocksource *cs);
	void (*disable)(struct clocksource *cs);
	void (*suspend)(struct clocksource *cs);
	void (*resume)(struct clocksource *cs);
};

/*
 * Clock source flags bits::
 */
#define CLOCK_SOURCE_IS_CONTINUOUS		0x01
#define CLOCK_SOURCE_MUST_VERIFY		0x02

#define CLOCK_SOURCE_WATCHDOG			0x10
#define CLOCK_SOURCE_VALID_FOR_HRES		0x20
#define CLOCK_SOURCE_UNSTABLE			0x40
#define CLOCK_SOURCE_SUSPEND_NONSTOP		0x80
#define CLOCK_SOURCE_RESELECT			0x100

/* simplify initialization of mask field */
#define CLOCKSOURCE_MASK(bits) (cycle_t)((bits) < 64 ? ((1ULL<<(bits))-1) : -1)

/*
 * Don't call __clocksource_register_scale directly, use
 * clocksource_register_hz/khz
 */
int __clocksource_register_scale(struct clocksource *cs, u32 scale, u32 freq);
void __clocksource_update_freq_scale(struct clocksource *cs, u32 scale, u32 freq);

/*
 * Don't call this unless you are a default clocksource
 * (AKA: jiffies) and absolutely have to.
 */
static inline int __clocksource_register(struct clocksource *cs)
{
	return __clocksource_register_scale(cs, 1, 0);
}

static inline int clocksource_register_hz(struct clocksource *cs, u32 hz)
{
	return __clocksource_register_scale(cs, 1, hz);
}

static inline int clocksource_register_khz(struct clocksource *cs, u32 khz)
{
	return __clocksource_register_scale(cs, 1000, khz);
}

static inline void __clocksource_update_freq_hz(struct clocksource *cs, u32 hz)
{
	__clocksource_update_freq_scale(cs, 1, hz);
}

static inline void __clocksource_update_freq_khz(struct clocksource *cs, u32 khz)
{
	__clocksource_update_freq_scale(cs, 1000, khz);
}

/**
 * clocksource_cyc2ns - converts clocksource cycles to nanoseconds
 * @cycles:	cycles
 * @mult:	cycle to nanosecond multiplier
 * @shift:	cycle to nanosecond divisor (power of two)
 *
 * Converts cycles to nanoseconds, using the given mult and shift.
 *
 * XXX - This could use some mult_lxl_ll() asm optimization
 */
static inline s64 clocksource_cyc2ns(cycle_t cycles, u32 mult, u32 shift)
{
	return ((u64) cycles * mult) >> shift;
}

extern struct clocksource * __init clocksource_default_clock(void);

extern void
clocks_calc_mult_shift(u32 *mult, u32 *shift, u32 from, u32 to, u32 minsec);

#endif /* _LEGO_CLOCKSOURCE_H_ */
