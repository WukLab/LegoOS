/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_DELAY_H_
#define _LEGO_DELAY_H_

#include <asm/delay.h>

/* Delay routines, using a pre-computed "loops_per_jiffy" value */
extern unsigned long loops_per_jiffy;

/* a good/find lpj provided by arch */
extern unsigned long lpj_fine;

/* Undefined functions to get compile-time errors */
extern void __bad_udelay(void);
extern void __bad_ndelay(void);

extern void __udelay(unsigned long usecs);
extern void __ndelay(unsigned long nsecs);
extern void __const_udelay(unsigned long xloops);
extern void __delay(unsigned long loops);

/*
 * The weird n/20000 thing suppresses a "comparison is always false due to
 * limited range of data type" warning with non-const 8-bit arguments.
 */

/* 0x10c7 is 2**32 / 1000000 (rounded up) */
#define udelay(n)							\
	({								\
		if (__builtin_constant_p(n)) {				\
			if ((n) / 20000 >= 1)				\
				 __bad_udelay();			\
			else						\
				__const_udelay((n) * 0x10c7ul);		\
		} else {						\
			__udelay(n);					\
		}							\
	})

/* 0x5 is 2**32 / 1000000000 (rounded up) */
#define ndelay(n)							\
	({								\
		if (__builtin_constant_p(n)) {				\
			if ((n) / 20000 >= 1)				\
				__bad_ndelay();				\
			else						\
				__const_udelay((n) * 5ul);		\
		} else {						\
			__ndelay(n);					\
		}							\
	})

/*
 * Using udelay() for intervals greater than a few milliseconds can
 * risk overflow for high loops_per_jiffy (high bogomips) machines. The
 * mdelay() provides a wrapper to prevent this.  For delays greater
 * than MAX_UDELAY_MS milliseconds, the wrapper is used.  Architecture
 * specific values can be defined in asm-???/delay.h as an override.
 * The 2nd mdelay() definition ensures GCC will optimize away the 
 * while loop for the common cases where n <= MAX_UDELAY_MS  --  Paul G.
 */
#define MAX_UDELAY_MS	5

#define mdelay(n) (\
	(__builtin_constant_p(n) && (n)<=MAX_UDELAY_MS) ? udelay((n)*1000) : \
	({unsigned long __ms=(n); while (__ms--) udelay(1000);}))

#endif /* _LEGO_DELAY_H_ */
