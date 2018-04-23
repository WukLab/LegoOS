/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/hashtable.h>

#include "../fit/fit_config.h"
#include "storage.h"
#include "common.h"
#include "replica.h"
#include "stat.h"

struct storage_manager_stat storage_manager_stats;

static const char *const storage_manager_stat_text[] = {
	"handle_replica_flush",
	"handle_replica_vma",
	"handle_replica_read",
	"handle_replica_write",
};

void print_storage_manager_stats(void)
{
	int i;

	BUILD_BUG_ON(NR_STORAGE_MANAGER_STAT_ITEMS != ARRAY_SIZE(storage_manager_stat_text));

	for (i = 0; i < NR_STORAGE_MANAGER_STAT_ITEMS; i++) {
		pr_crit("%s: %lu\n", storage_manager_stat_text[i],
			atomic_long_read(&storage_manager_stats.stat[i]));
	}
}
