/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MEMORY_STAT_H_
#define _LEGO_MEMORY_STAT_H_

#include <lego/atomic.h>

enum memory_manager_stat_item {
	/* Handler */
	HANDLE_PCACHE_MISS,
	HANDLE_PCACHE_FLUSH,
	HANDLE_PCACHE_REPLICA,
	HANDLE_P2M_MMAP,
	HANDLE_P2M_MUNMAP,
	HANDLE_P2M_BRK,
	HANDLE_M2M_MMAP,
	HANDLE_M2M_MUNMAP,

	HANDLE_READ,
	HANDLE_WRITE,

	NR_BATCHED_LOG_FLUSH,

	NR_MEMORY_MANAGER_STAT_ITEMS,
};

struct memory_manager_stat {
	atomic_long_t stat[NR_MEMORY_MANAGER_STAT_ITEMS];
};

extern struct memory_manager_stat memory_manager_stats;

static inline unsigned long mm_stat(enum memory_manager_stat_item i)
{
	return atomic_long_read(&memory_manager_stats.stat[i]);
}

#ifdef CONFIG_COUNTER_MEMORY_HANDLER
static inline void inc_mm_stat(enum memory_manager_stat_item i)
{
	atomic_long_inc(&memory_manager_stats.stat[i]);
}

void print_memory_manager_stats(void);
#else
static inline void inc_mm_stat(enum memory_manager_stat_item i) { }
static inline void print_memory_manager_stats(void) { }
#endif

#endif /* _LEGO_MEMORY_STAT_H_ */
