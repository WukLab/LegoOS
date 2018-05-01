/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/kernel.h>
#include <memory/stat.h>


struct memory_manager_stat memory_manager_stats;

static const char *const memory_manager_stat_text[] = {
	/* Handler group */
	"handle_pcache_miss",
	"handle_pcache_flush",
	"handle_pcache_replica",
	"handle_p2m_mmap",
	"handle_p2m_munmap",
	"handle_p2m_brk",
	"handle_m2m_mmap",
	"handle_m2m_munmap",

	/* fs related */
	"handle_read",
	"handle_write",

	/* replication */
	"nr_batched_log_flush"
};

#ifdef CONFIG_COUNTER_MEMORY_HANDLER
void print_memory_manager_stats(void)
{
	int i;

	BUILD_BUG_ON(NR_MEMORY_MANAGER_STAT_ITEMS != ARRAY_SIZE(memory_manager_stat_text));

	for (i = 0; i < NR_MEMORY_MANAGER_STAT_ITEMS; i++) {
		pr_info("%s: %lu\n", memory_manager_stat_text[i],
			atomic_long_read(&memory_manager_stats.stat[i]));
	}
}
#endif
