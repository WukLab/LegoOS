/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file describes helpers to play with per-zone and per-node
 * counters. Other VM activies such as TLB flush are processor specific.
 */

#ifndef _LEGO_VMSTAT_H_
#define _LEGO_VMSTAT_H_

#include <lego/atomic.h>
#include <lego/mm.h>

/*
 * Zone and node-based page accounting with per cpu differentials.
 */
extern atomic_long_t vm_zone_stat[NR_VM_ZONE_STAT_ITEMS];
extern atomic_long_t vm_node_stat[NR_VM_NODE_STAT_ITEMS];

static inline void zone_page_state_add(long x, struct zone *zone,
				 enum zone_stat_item item)
{
	atomic_long_add(x, &zone->vm_stat[item]);
	atomic_long_add(x, &vm_zone_stat[item]);
}

static inline void node_page_state_add(long x, struct pglist_data *pgdat,
				 enum node_stat_item item)
{
	atomic_long_add(x, &pgdat->vm_stat[item]);
	atomic_long_add(x, &vm_node_stat[item]);
}

static inline unsigned long global_page_state(enum zone_stat_item item)
{
	long x = atomic_long_read(&vm_zone_stat[item]);
#ifdef CONFIG_SMP
	if (x < 0)
		x = 0;
#endif
	return x;
}

static inline unsigned long global_node_page_state(enum node_stat_item item)
{
	long x = atomic_long_read(&vm_node_stat[item]);
#ifdef CONFIG_SMP
	if (x < 0)
		x = 0;
#endif
	return x;
}

static inline unsigned long zone_page_state(struct zone *zone,
					enum zone_stat_item item)
{
	long x = atomic_long_read(&zone->vm_stat[item]);
#ifdef CONFIG_SMP
	if (x < 0)
		x = 0;
#endif
	return x;
}

/*
 * XXX:
 * This equals to linux non-SMP version
 * defenitly will add a lot overhead..
 * Anyway, add this first and come back later.
 */

static inline void __mod_zone_page_state(struct zone *zone,
			enum zone_stat_item item, long delta)
{
	zone_page_state_add(delta, zone, item);
}

static inline void __mod_node_page_state(struct pglist_data *pgdat,
			enum node_stat_item item, int delta)
{
	node_page_state_add(delta, pgdat, item);
}

static inline void __inc_zone_state(struct zone *zone, enum zone_stat_item item)
{
	atomic_long_inc(&zone->vm_stat[item]);
	atomic_long_inc(&vm_zone_stat[item]);
}

static inline void __inc_node_state(struct pglist_data *pgdat, enum node_stat_item item)
{
	atomic_long_inc(&pgdat->vm_stat[item]);
	atomic_long_inc(&vm_node_stat[item]);
}

static inline void __dec_zone_state(struct zone *zone, enum zone_stat_item item)
{
	atomic_long_dec(&zone->vm_stat[item]);
	atomic_long_dec(&vm_zone_stat[item]);
}

static inline void __dec_node_state(struct pglist_data *pgdat, enum node_stat_item item)
{
	atomic_long_dec(&pgdat->vm_stat[item]);
	atomic_long_dec(&vm_node_stat[item]);
}

static inline void __inc_zone_page_state(struct page *page,
			enum zone_stat_item item)
{
	__inc_zone_state(page_zone(page), item);
}

static inline void __inc_node_page_state(struct page *page,
			enum node_stat_item item)
{
	__inc_node_state(page_pgdat(page), item);
}

static inline void __dec_zone_page_state(struct page *page,
			enum zone_stat_item item)
{
	__dec_zone_state(page_zone(page), item);
}

static inline void __dec_node_page_state(struct page *page,
			enum node_stat_item item)
{
	__dec_node_state(page_pgdat(page), item);
}

#define inc_zone_page_state __inc_zone_page_state
#define dec_zone_page_state __dec_zone_page_state
#define mod_zone_page_state __mod_zone_page_state

#define inc_node_page_state __inc_node_page_state
#define dec_node_page_state __dec_node_page_state
#define mod_node_page_state __mod_node_page_state

#define inc_zone_state __inc_zone_state
#define inc_node_state __inc_node_state
#define dec_zone_state __dec_zone_state

#endif /* _LEGO_VMSTAT_H_ */
