/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/kernel.h>
#include <lego/fit_ibapi.h>
#include <processor/pcache.h>

struct pcache_event_stat pcache_event_stats;

static const char *const pcache_event_text[] = {
	"nr_pgfault",
	"nr_pgfault_code",

	"nr_clflush",
	"nr_clflush_clean_skipped",
	"nr_clflush_fail",
	"nr_clflush_piggyback_fallback",

	/* write-protection fault */
	"nr_pgfault_wp",
	"nr_pgfault_wp_cow",
	"nr_pgfault_wp_reuse",

	"nr_pgfault_due_to_concurrent_eviction",	/* perset list specific */

	"nr_pcache_fill_zerofill",
	"nr_pcache_fill_from_memory",
	"nr_pcache_fill_from_memory_piggyback",
	"nr_pcache_fill_from_memory_piggyback_fallback",
	"nr_pcache_fill_from_victim",			/* victim cache specific */

	"nr_pcache_eviction_triggered",
	"nr_pcache_eviction_eagain_freeable",
	"nr_pcache_eviction_eagain_concurrent",
	"nr_pcache_eviction_failure_find",
	"nr_pcache_eviction_failure_evict",
	"nr_pcache_eviction_succeed",

	"nr_pset_list_lookup",
	"nr_pset_list_hit",

        "nr_victim_lookup",
        "nr_victim_hit",

	"nr_victim_eviction_triggered",
	"nr_victim_eviction_eagain",
	"nr_victim_eviction_succeed",

	/* Victim internal debug counter */
	"nr_victim_prepare_insert",
	"nr_victim_finish_insert",

	/* Victim flush counters */
	"nr_victim_flush_submitted_clean",
	"nr_victim_flush_submitted_dirty",
	"nr_victim_flush_finished_dirty",
	"nr_victim_flush_async_run",
	"nr_victim_flush_sync",

	/* sweep */
	"nr_sweep_run",
	"nr_sweep_nr_pset",
	"nr_sweep_nr_moved_pcm",

	"nr_mremap_pset_same",
	"nr_mremap_pset_diff",

	"nr_pcache_rmap_alloc",
	"nr_pcache_rmap_alloc_kmalloc",
	"nr_pcache_rmap_free",
	"nr_pcache_rmap_free_kmalloc",

	"nr_pcache_pee_alloc",
	"nr_pcache_pee_alloc_kmalloc",
	"nr_pcache_pee_free",
	"nr_pcache_pee_free_kmalloc",
};

void print_pcache_events(void)
{
	int i;

	BUILD_BUG_ON(NR_PCACHE_EVENT_ITEMS != ARRAY_SIZE(pcache_event_text));

	for (i = 0; i < NR_PCACHE_EVENT_ITEMS; i++) {
		pr_info("%s: %lu\n", pcache_event_text[i],
			atomic_long_read(&pcache_event_stats.event[i]));
	}
}
