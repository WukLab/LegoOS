/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/wait.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/hash.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/syscalls.h>
#include <lego/jiffies.h>
#include <processor/pcache.h>
#include <processor/processor.h>

DEFINE_PER_CPU(struct pcache_event_stat, pcache_event_stats) = {{0}};

static const char *const pcache_event_text[] = {
	"nr_pgfault",
	"nr_wp_pgfault",
	"nr_wp_cow_pgfault",
	"nr_concurrent_eviction",
	"nr_cache_fill",
	"nr_evictions",
	"nr_victim_hit",
};

void sum_pcache_events(struct pcache_event_stat *buf)
{
	int cpu, i;
	struct pcache_event_stat *this;

	memset(buf->event, 0, NR_PCACHE_EVENT_ITEMS * sizeof(unsigned long));

	for_each_online_cpu(cpu) {
		this = &per_cpu(pcache_event_stats, cpu);
		for (i = 0; i < NR_PCACHE_EVENT_ITEMS; i++)
			buf->event[i] += this->event[i];
	}
}

void print_pcache_events(void)
{
	struct pcache_event_stat stat;
	int i;

	BUILD_BUG_ON(NR_PCACHE_EVENT_ITEMS > ARRAY_SIZE(pcache_event_text));

	sum_pcache_events(&stat);
	for (i = 0; i < NR_PCACHE_EVENT_ITEMS; i++) {
		pr_info("%s: %lu\n", pcache_event_text[i], stat.event[i]);
	}
}
