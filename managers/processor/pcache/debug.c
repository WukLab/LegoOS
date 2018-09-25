/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/checksum.h>
#include <lego/tracepoint.h>
#include <processor/pcache.h>

#include "piggyback.h"

#define __def_pcacheflag_names					\
	{1UL << PC_locked,		"locked"	},	\
	{1UL << PC_valid,		"valid"		},	\
	{1UL << PC_dirty,		"dirty"		},	\
	{1UL << PC_reclaim,		"reclaim"	},	\
	{1UL << PC_writeback,		"writeback"	},	\
	{1UL << PC_piggyback,		"piggyback"	},	\
	{1UL << PC_piggyback,		"piggybackC"	}

const struct trace_print_flags pcacheflag_names[] = {
	__def_pcacheflag_names,
	{0, NULL}
};

/**
 * dump_pcache_meta
 * @pcm: pcache line in question
 * @reason: why you dump
 *
 * Dump current state of a pcache line, including mapcount, status.
 */
void dump_pcache_meta(struct pcache_meta *pcm, const char *reason)
{
	pr_debug("pcache:%p mapcount:%d refcount:%d flags:(%pGc) kva: %p\n",
		pcm, atomic_read(&pcm->mapcount),
		atomic_read(&pcm->_refcount), &pcm->bits,
		pcache_meta_to_kva(pcm));
	if (reason)
		pr_debug("pcache dumped because: %s\n", reason);
}

static const char *RMAP_CALLER_NAME[] = {
	"fill_page_remote",
	"zerofill",
	"victim_fill",
	"cow",
	"fork",
	"mremap_slowpath",
};

/**
 * dump_pcache_rmap
 * @rmap: the reverse map in question
 *
 * Dump a pcache_rmap, including its owner, flags, user va and pte.
 */
void dump_pcache_rmap(struct pcache_rmap *rmap, const char *reason)
{
	pte_t *ptep = rmap->page_table;

	pr_debug("rmap:%p flags:%#lx owner-tgid:%u user_va:%#lx ptep:%p caller: %s\n",
		rmap, rmap->flags, rmap->owner_process->pid, rmap->address, ptep,
		RMAP_CALLER_NAME[rmap->caller]);
	dump_pte(ptep, NULL);

	if (reason)
		pr_debug("pcache_rmap dumped because: %s\n", reason);
}

static int __dump_pcache_rmaps(struct pcache_meta *pcm,
			       struct pcache_rmap *rmap, void *arg)
{
	dump_pcache_rmap(rmap, NULL);
	return PCACHE_RMAP_AGAIN;
}

void dump_pcache_rmaps_locked(struct pcache_meta *pcm)
{
	struct rmap_walk_control rwc = {
		.rmap_one = __dump_pcache_rmaps,
	};

	rmap_walk(pcm, &rwc);
}

void dump_pcache_rmaps(struct pcache_meta *pcm)
{
	lock_pcache(pcm);
	dump_pcache_rmaps_locked(pcm);
	unlock_pcache(pcm);
}

static DEFINE_SPINLOCK(dump_pset_lock);

void dump_pset(struct pcache_set *pset)
{
	struct pcache_meta *pcm;

	spin_lock(&dump_pset_lock);

	pr_debug("pset:%p set_idx: %lu nr_lru:%d\n",
		pset, pcache_set_to_set_index(pset),
		IS_ENABLED(CONFIG_PCACHE_EVICT_LRU) ? atomic_read(&pset->nr_lru) : 0);

	pcm = this_cpu_read(piggybacker);
	if (pcm)
		dump_pcache_meta(pcm, "This is piggybacker");

	pr_info("Free List\n");
	spin_lock(&pset->free_lock);
	list_for_each_entry(pcm, &pset->free_head, free_list) {
		dump_pcache_meta(pcm, NULL);
		dump_pcache_rmaps(pcm);
	}
	spin_unlock(&pset->free_lock);

	pr_info("LRU List\n");
	spin_lock(&pset->lru_lock);
	list_for_each_entry(pcm, &pset->lru_list, lru) {
		dump_pcache_meta(pcm, NULL);
		dump_pcache_rmaps(pcm);
	}
	spin_unlock(&pset->lru_lock);
	spin_unlock(&dump_pset_lock);
}

/**
 * pcache_line_csum
 * @pcm: pcache line in question
 *
 * Get a 32-bit checksum of the cache line.
 */
__wsum pcache_line_csum(struct pcache_meta *pcm)
{
	void *pcacheline;

	pcacheline = pcache_meta_to_kva(pcm);
	return csum_partial(pcacheline, PCACHE_LINE_SIZE, 0);
}

/**
 * dump_pcache_line
 * @pcm: pcache line in question
 * @reason: why you dump
 *
 * Dump @pcm's stata and all its cache line content. Checksum of
 * this cache line is also printed as prefix.
 *
 * Be careful when you use this function. It will print a lot
 * useless messages. If you just want to know the integrity of the
 * cache line, compare checsum might be a better idea.
 */
void dump_pcache_line(struct pcache_meta *pcm, const char *reason)
{
	__wsum csum;
	char csum_s[64];

	csum = pcache_line_csum(pcm);
	sprintf(csum_s, "csum(%#x)--", csum);

	dump_pcache_meta(pcm, reason);
	print_hex_dump_bytes(csum_s, DUMP_PREFIX_OFFSET,
		pcache_meta_to_kva(pcm), PCACHE_LINE_SIZE);
}

/*
 * Use with caution.
 * Make sure no pcache activities are in progress.
 */
void dump_valid_pcache(void)
{
	struct pcache_meta *pcm;
	struct pcache_set *pset;
	int way_idx, set_idx;

	pcache_for_each_set(pset, set_idx) {
		pcache_for_each_way_set(pcm, pset, way_idx) {
			if (PcacheValid(pcm)) {
				dump_pcache_meta(pcm, NULL);
				dump_pcache_rmaps(pcm);
			}
		}
	}
}
