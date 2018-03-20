/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Generate definitions needed by the preprocessor.
 * This code generates raw asm output which is post-processed
 * to extract and format the required data.
 */

#define __GENERATING_BOUNDS_H

#include <lego/kbuild.h>

/* Include headers that define the enum constants of interest */
#include <lego/log2.h>
#include <lego/mm_types.h>
#include <lego/mm_zone.h>
#include <lego/page-flags.h>
#include <lego/spinlock.h>

void wuklabisawesome(void)
{
	/* The enum constants to put into include/generated/bounds.h */
	DEFINE(MAX_NR_ZONES, __MAX_NR_ZONES);
	DEFINE(NR_PAGEFLAGS, __NR_PAGEFLAGS);
#ifdef CONFIG_SMP
	DEFINE(NR_CPU_BITS, ilog2(CONFIG_NR_CPUS));
#endif
	DEFINE(SPINLOCK_SIZE, sizeof(spinlock_t));
	DEFINE(STRUCT_PAGE_SIZE, sizeof(struct page));
}
