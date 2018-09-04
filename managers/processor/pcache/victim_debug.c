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

/* To avoid tons of mixed messages */
static DEFINE_SPINLOCK(victim_dump_lock);

#define __def_victimflag_names						\
	{1UL << PCACHE_VICTIM_locked,		"locked"	},	\
	{1UL << PCACHE_VICTIM_allocated,	"allocated"	},	\
	{1UL << PCACHE_VICTIM_usable,		"usable"	},	\
	{1UL << PCACHE_VICTIM_hasdata,		"hasdata"	},	\
	{1UL << PCACHE_VICTIM_writeback,	"writeback"	},	\
	{1UL << PCACHE_VICTIM_waitflush,	"waitflush"	},	\
	{1UL << PCACHE_VICTIM_flushed,		"flushed"	},	\
	{1UL << PCACHE_VICTIM_reclaim,		"reclaim"	},	\
	{1UL << PCACHE_VICTIM_fillfree,		"fillfree"	},	\
	{1UL << PCACHE_VICTIM_fillfree,		"nohit"		},

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

static void __dump_pcache_victim_simple(struct pcache_victim_meta *victim)
{
	vdump(" victim[%d]:%p refcount:%d nr_fill:%d max_fill:%d locked:%d flags:(%#lx)(%pGV) "
		 "pcm:%p pset:%p\n",
		victim_index(victim), victim, atomic_read(&victim->_refcount),
		atomic_read(&victim->nr_fill_pcache), atomic_read(&victim->max_nr_fill_pcache),
		spin_is_locked(&victim->lock),
		victim->flags, &victim->flags, victim->pcm, victim->pset);
}

void dump_pcache_victim_simple(struct pcache_victim_meta *victim)
{
	spin_lock(&victim_dump_lock);
	__dump_pcache_victim_simple(victim);
	spin_unlock(&victim_dump_lock);
}

static void __dump_pcache_victim(struct pcache_victim_meta *victim,
				 const char *reason)
{
	__dump_pcache_victim_simple(victim);
	dump_pcache_victim_hits(victim);
	__dump_pcache_victim_simple(victim);

	if (victim->pcm)
		dump_pcache_meta(victim->pcm, "dump_victim");

	if (victim->pset) {
		vdump("    rmap to pset_idx: %lu nr_hint_victims: %d nr_lru: %d\n",
			pcache_set_to_set_index(victim->pset), pcache_set_victim_nr(victim->pset),
			IS_ENABLED(CONFIG_PCACHE_EVICT_LRU) ? atomic_read(&victim->pset->nr_lru) : 0);
	}

	if (reason)
		vdump("    victim dumped because: %s\n", reason);
}

void dump_pcache_victim(struct pcache_victim_meta *victim, const char *reason)
{
	spin_lock(&victim_dump_lock);
	__dump_pcache_victim(victim, reason);
	spin_unlock(&victim_dump_lock);
}

static int nr_dumped_all_victim;
static int nr_dumped_flush_queue;

static void __dump_all_victim(void)
{
	struct pcache_victim_meta *v;
	int index;

	vdump("  --   Start Dump Victim Cache [%d] total: %d\n",
		nr_dumped_all_victim, VICTIM_NR_ENTRIES);

	for_each_victim(v, index)
		__dump_pcache_victim(v, NULL);

	vdump("  --   End Dump Victim Cache [%d]\n\n", nr_dumped_all_victim++);
}

static void __dump_victim_flush_queue(void)
{
	struct victim_flush_job *job;
	struct pcache_victim_meta *v;

	vdump("  --  Start Dump Victim Flush Queue [%d]\n", nr_dumped_flush_queue);

	if (list_empty(&victim_flush_queue)) {
		vdump("     (empty) [%d]\n", nr_dumped_flush_queue);
		goto out;
	}

	list_for_each_entry(job, &victim_flush_queue, next) {
		v = job->victim;
		BUG_ON(!v);
		__dump_pcache_victim_simple(v);
	}

out:
	vdump("  --  End Dump Victim Flush Queue [%d]\n\n", nr_dumped_flush_queue++);
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
