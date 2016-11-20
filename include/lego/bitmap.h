/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * bitmaps provide bit arrays that consume one or more unsigned longs.
 * The bitmap interface and available operations are listed here.
 */

#ifndef _LEGO_BITMAP_H_
#define _LEGO_BITMAP_H_

#include <lego/bitops.h>
#include <lego/kernel.h>

extern int __bitmap_equal(const unsigned long *bitmap1,
			  const unsigned long *bitmap2, unsigned int nbits);
extern int __bitmap_weight(const unsigned long *bitmap, unsigned int nbits);

#define small_const_nbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)

static inline int bitmap_equal(const unsigned long *src1,
			const unsigned long *src2, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		return !((*src1 ^ *src2) & BITMAP_LAST_WORD_MASK(nbits));
	return __bitmap_equal(src1, src2, nbits);
}

static __always_inline int bitmap_weight(const unsigned long *src, unsigned int nbits)
{
	return __bitmap_weight(src, nbits);
}

#endif /* _LEGO_BITMAP_H_ */
