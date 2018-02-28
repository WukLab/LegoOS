/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * For sys_getcpu
 */

#ifndef _LEGO_GETCPU_H_
#define _LEGO_GETCPU_H_

/* Cache for getcpu() to speed it up. Results might be a short time
   out of date, but will be faster.

   User programs should not refer to the contents of this structure.
   I repeat they should not refer to it. If they do they will break
   in future kernels.

   It is only a private cache for vgetcpu(). It will change in future kernels.
   The user program must store this information per thread (__thread)
   If you want 100% accurate information pass NULL instead. */
struct getcpu_cache {
	unsigned long blob[128 / sizeof(long)];
};

#endif /* _LEGO_GETCPU_H_ */
