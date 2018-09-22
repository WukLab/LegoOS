/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file serves as the .config file of Lego storage manager
 */

#ifndef _LEGO_STORAGE_CONFIG_STORAGE_
#define _LEGO_STORAGE_CONFIG_STORAGE_

#define STORAGE_DEBUG_CORE
#define STORAGE_DEBUG_OPEN
#define STORAGE_DEBUG_STAT
#define STORAGE_DEBUG_ACCESS
#define STORAGE_DEBUG_READ_WRITE

/*
 * If STORAGE_BYPASS_PAGE_CACHE is enabled, we need to have the user
 * context to do mmap. That means we have use the current insmod thread
 * to do so. That further means the insmod thread will never return...
 *
 * For non-storage-intensive workload, you can disable this.
 */
#if 0
# define STORAGE_BYPASS_PAGE_CACHE
#endif

#endif /* _LEGO_STORAGE_CONFIG_STORAGE_ */
