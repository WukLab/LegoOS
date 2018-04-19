/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/jiffies.h>
#include <lego/kthread.h>
#include <lego/memblock.h>
#include <lego/completion.h>
#include <processor/pcache.h>
#include <processor/processor.h>

#define __def_victimflag_names						\
	{1UL << PCACHE_VICTIM_locked,		"locked"	},	\
	{1UL << PCACHE_VICTIM_allocated,	"allocated"	},	\
	{1UL << PCACHE_VICTIM_usable,		"usable"	},	\
	{1UL << PCACHE_VICTIM_hasdata,		"hasdata"	},	\
	{1UL << PCACHE_VICTIM_writeback,	"writeback"	},	\
	{1UL << PCACHE_VICTIM_waitflush,	"waitflush"	},	\
	{1UL << PCACHE_VICTIM_flushed,		"flushed"	},	\
	{1UL << PCACHE_VICTIM_reclaim,		"reclaim"	},

const struct trace_print_flags victimflag_names[] = {
	__def_victimflag_names
	{0, NULL}
};

#define vdump(fmt, ...)	\
	pr_info("CPU%d PID%d " fmt, smp_processor_id(), current->pid, __VA_ARGS__)

void dump_pcache_victim_hits(struct pcache_victim_meta *victim)
{
	struct pcache_victim_hit_entry *entry;
	int i = 0;

	if (list_empty(&victim->hits)) {
		vdump("    hit[%d] (empty)\n", i);
		return;
	}

	list_for_each_entry(entry, &victim->hits, next) {
		vdump("    hit[%d] owner:%u m_nid:%d rep_nid:%d addr: %#lx\n",
			i++, entry->tgid, entry->m_nid, entry->rep_nid,
			entry->address);
	}
}

void dump_pcache_victim_simple(struct pcache_victim_meta *victim)
{
	vdump(" victim:%p index:%d refcount:%d nr_fill:%d locked:%d flags:(%pGV) "
		 "pcm:%p pset:%p\n",
		victim, victim_index(victim), atomic_read(&victim->_refcount),
		atomic_read(&victim->nr_fill_pcache), spin_is_locked(&victim->lock),
		&victim->flags, victim->pcm, victim->pset);
}

void dump_pcache_victim(struct pcache_victim_meta *victim, const char *reason)
{
	dump_pcache_victim_simple(victim);
	dump_pcache_victim_hits(victim);

	if (victim->pcm)
		dump_pcache_meta(victim->pcm, "dump_victim");

	if (victim->pset) {
		vdump("    rmap to pset:%p set_idx: %lu nr_lru:%d\n",
			victim->pset, pcache_set_to_set_index(victim->pset),
			IS_ENABLED(CONFIG_PCACHE_EVICT_LRU) ? atomic_read(&victim->pset->nr_lru) : 0);
	}

	if (reason)
		vdump("    victim dumped because: %s\n", reason);
}

/* To avoid tons of mixed messages */
static DEFINE_SPINLOCK(victim_dump_lock);
static bool victim_dumped = false;

static int nr_dumped_all_victim;
static int nr_dumped_flush_queue;

static void __dump_all_victim(void)
{
	struct pcache_victim_meta *v;
	int index;

	if (!victim_dumped)
		victim_dumped = true;
	else
		return;

	vdump("  --   Start Dump Victim Cache [%d]\n", nr_dumped_all_victim);
	for_each_victim(v, index)
		dump_pcache_victim(v, NULL);
	vdump("  --   End Dump Victim Cache [%d]\n\n", nr_dumped_all_victim++);
}

void __dump_victim_flush_queue(void)
{
	struct victim_flush_job *job;
	struct pcache_victim_meta *v;

	spin_lock(&victim_flush_lock);
	vdump("  --  Start Dump Victim Flush Queue [%d]\n", nr_dumped_flush_queue);

	if (list_empty(&victim_flush_queue)) {
		vdump("     (empty) [%d]\n", nr_dumped_flush_queue);
		goto unlock;
	}

	list_for_each_entry(job, &victim_flush_queue, next) {
		v = job->victim;
		BUG_ON(!v);
		dump_pcache_victim_simple(v);
	}

unlock:
	vdump("  --  End Dump Victim Flush Queue [%d]\n\n", nr_dumped_flush_queue++);
	spin_unlock(&victim_flush_lock);
}

void dump_all_victim(void)
{
	spin_lock(&victim_dump_lock);
	__dump_all_victim();
	spin_unlock(&victim_dump_lock);
}

void dump_victim_flush_queue(void)
{
	spin_lock(&victim_dump_lock);
	__dump_victim_flush_queue();
	spin_unlock(&victim_dump_lock);
}

void dump_victim_lines_and_queue(void)
{
	spin_lock(&victim_dump_lock);
	__dump_all_victim();
	__dump_victim_flush_queue();
	spin_unlock(&victim_dump_lock);
}
