/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_STORAGE_STAT_H_
#define _LEGO_STORAGE_STAT_H_

enum storage_manager_stat_item {
	HANDLE_REPLICA_FLUSH,
	HANDLE_REPLICA_VMA,
	HANDLE_REPLICA_READ,
	HANDLE_REPLICA_WRITE,

	NR_STORAGE_MANAGER_STAT_ITEMS,
};

struct storage_manager_stat {
	atomic_long_t stat[NR_STORAGE_MANAGER_STAT_ITEMS];
};

extern struct storage_manager_stat storage_manager_stats;

static inline void inc_storage_stat(enum storage_manager_stat_item i)
{
	atomic_long_inc(&storage_manager_stats.stat[i]);
}

void print_storage_manager_stats(void);

#endif /* _LEGO_STORAGE_STAT_H_ */
