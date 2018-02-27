/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Internal header file of memory pcache handling subsystem
 */

#ifndef _MEMORY_PCACHE_INTERNAL_H_
#define _MEMORY_PCACHE_INTERNAL_H_

void do_mmap_prefetch(struct lego_task_struct *p, u64 vaddr,
		      u32 flags, u32 nr_pages);

#endif /* _MEMORY_PCACHE_INTERNAL_H_ */
