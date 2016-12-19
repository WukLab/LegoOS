/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MM_DEBUG_H_
#define _LEGO_MM_DEBUG_H_

/*
 * MM Debug Related
 */
#define VM_WARN_ON(cond)	WARN_ON(cond)
#define VM_WARN_ON_ONCE(cond)	WARN_ON_ONCE(cond)
#define VM_BUG_ON(cond)		BUG_ON(cond)
#define VM_BUG_ON_PAGE(cond, page)					\
	do {								\
		if (unlikely(cond)) {					\
			BUG();						\
		}							\
	} while (0)

#endif /* _LEGO_MM_DEBUG_H_ */
