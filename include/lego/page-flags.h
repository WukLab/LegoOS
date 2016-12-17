/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PAGE_FLAGS_H_
#define _LEGO_PAGE_FLAGS_H_

#ifndef __GENERATING_BOUNDS_H
#include <generated/bounds.h>
#endif

/*
 * page->flags bits:
 *
 */
enum pageflags {
	PG_locked,
	PG_referenced,
	PG_dirty,

	__NR_PAGEFLAGS,
};

#endif /* _LEGO_PAGE_FLAGS_H_ */
