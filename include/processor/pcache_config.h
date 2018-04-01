/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROCESSOR_PCACHE_CONFIG_H_
#define _LEGO_PROCESSOR_PCACHE_CONFIG_H_

#include <lego/const.h>

/*
 * This file should only be included by Processor and Memory managers.
 */

#ifdef CONFIG_PCACHE_LINE_SIZE_SHIFT
# define PCACHE_LINE_SIZE_SHIFT		(CONFIG_PCACHE_LINE_SIZE_SHIFT)
#else
# define PCACHE_LINE_SIZE_SHIFT		(12)
#endif

#ifdef CONFIG_PCACHE_ASSOCIATIVITY_SHIFT
# define PCACHE_ASSOCIATIVITY_SHIFT	(CONFIG_PCACHE_ASSOCIATIVITY_SHIFT)
#else
# define PCACHE_ASSOCIATIVITY_SHIFT	(3)
#endif

#define PCACHE_LINE_SIZE		(_AC(1,UL) << PCACHE_LINE_SIZE_SHIFT)
#define PCACHE_LINE_MASK		(~(PCACHE_LINE_SIZE-1))
#define PCACHE_ASSOCIATIVITY		(_AC(1,UL) << PCACHE_ASSOCIATIVITY_SHIFT)

#define PCACHE_LINE_NR_PAGES		(PCACHE_LINE_SIZE / PAGE_SIZE)

#endif /* _LEGO_PROCESSOR_PCACHE_CONFIG_H_ */
