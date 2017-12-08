/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Why victim insertion is divided into two steps?
 *
 * Let us first see if we do insertion in one step:
 * ----------------------------------------------------------------------------
 * |        CPU 0                             |    CPU 1                      |
 * |                                          |                               |
 * |  [victim_insert]                         |                               |
 * |    - add meta to list                    |                               |
 * |    - start copy from pcache to victim    |                               |
 * |      ..                                  |                               |
 * |      ..                                  |   [write to this pcache line] |
 * |      ..                                  |     go through                |
 * |    - finish copy from pcache to victim   |                               |
 * |    - start flush victim back to memory   |                               |
 * |      ..                                  |                               |
 * |      ..                                  |                               |
 * |      ..                                  |                               |
 * |    - finish flush                        |                               |
 * |  [try_to_unmap]                          |                               |
 * ----------------------------------------------------------------------------
 *
 * The line copied from pcache to victim is basically broken when CPU 0
 * finished copying. And this violates the *atomicity* guarantees of clflush.
 *
 * Now, we divide victim_insert into two steps:
 * ----------------------------------------------------------------------------
 * |        CPU 0                              |    CPU 1                     |
 * |                                           |                              |
 * |  [victim_prepare_insert]                  |                              |
 * |    - add meta to list                     |                              |
 * |  [try_to_unmap]                           |                              |
 * |  [victim_finish_insert]                   |                              |
 * |    - start copy from pcache to victim     |                              |
 * |      ..                                   |                              |
 * |      ..                                   |  [write to this pcache line] |
 * |      ..                                   |    pgfault!                  |
 * |    - finish copy from pcache to victim    |                              |
 * |    - start flush victim back to memory    |                              |
 * |      ..                                   |                              |
 * |      ..                                   |                              |
 * |      ..                                   |                              |
 * |    - finish flush                         |                              |
 * ----------------------------------------------------------------------------
 *
 * The copy is performed after ptes are unmapped, which prevent the copy from
 * random writes, and ensures the integrity of cacheline.
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

struct pcache_victim_meta *pcache_victim_meta_map __read_mostly;
void *pcache_victim_data_map __read_mostly;

void dump_pcache_victim(struct pcache_victim_meta *pvm, const char *reason)
{

}

static inline struct pcache_victim_meta *
victim_alloc_fastpath(void)
{
	int index;
	struct pcache_victim_meta *v;

	/*
	 * TestSet is atomic Read-Modify-Write instruction,
	 * so no need to use another lock to protect this loop.
	 */
	for_each_victim(v, index) {
		if (likely(!TestSetVictimAllocated(v))) {
			return v;
		}
	}
	return NULL;
}

static struct pcache_victim_meta *
victim_alloc_slowpath(void)
{
	panic("victim cache eviction needed!");
	return NULL;
}

static struct pcache_victim_meta *victim_alloc(void)
{
	struct pcache_victim_meta *v;

	v = victim_alloc_fastpath();
	if (likely(v))
		goto out;

	v = victim_alloc_slowpath();
	if (likely(v))
		goto out;
	return NULL;

out:
	/* May need further initilization if needed */
	return v;
}

static void victim_free(struct pcache_victim_meta *v)
{
	PCACHE_BUG_ON_VICTIM(!VictimAllocated(v) || VictimLocked(v) ||
			      VictimWriteback(v), v);

	ClearVictimAllocated(v);
}

static inline struct pcache_victim_hit_entry *
alloc_victim_hit_entry(void)
{
	struct pcache_victim_hit_entry *entry;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (entry) {
		INIT_LIST_HEAD(&entry->next);
	}
	return entry;
}

/*
 * Check if @victim belongs to @address+@tsk
 * Return TRUE if hit, FALSE on miss.
 */
bool victim_check_hit_entry(struct pcache_victim_meta *victim,
			    unsigned long address, struct task_struct *tsk)
{
	struct pcache_victim_hit_entry *entry;
	bool hit = false;

	address &= PAGE_MASK;
	spin_lock(&victim->lock);
	list_for_each_entry(entry, &victim->hits, next) {
		if (entry->address == address &&
		    same_thread_group(entry->owner, tsk)) {
			hit = true;
			break;
		}
	}
	spin_unlock(&victim->lock);

	return hit;
}

static int victim_insert_hit_entry(struct pcache_meta *pcm,
				   struct pcache_rmap *rmap, void *arg)
{
	struct pcache_victim_meta *victim = arg;
	struct pcache_victim_hit_entry *hit;

	hit = alloc_victim_hit_entry();
	if (!hit)
		return PCACHE_RMAP_FAILED;

	hit->address = rmap->address & PAGE_MASK;
	hit->owner = rmap->owner;

	spin_lock(&victim->lock);
	list_add(&hit->next, &victim->hits);
	spin_unlock(&victim->lock);

	return PCACHE_RMAP_AGAIN;
}

static inline int
victim_insert_hit_entries(struct pcache_victim_meta *victim, struct pcache_meta *pcm)
{
	struct rmap_walk_control rwc = {
		.arg = victim,
		.rmap_one = victim_insert_hit_entry,
	};

	rmap_walk(pcm, &rwc);

	return 0;
}

struct pcache_victim_meta *
victim_prepare_insert(struct pcache_set *pset, struct pcache_meta *pcm)
{
	int ret;
	struct pcache_victim_meta *victim;

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);

	victim = victim_alloc();
	if (!victim)
		return ERR_PTR(-ENOMEM);

	/* For two-step insertion */
	victim->pcm = pcm;

	/*
	 * Save the rmap info into victim cache's own
	 * hit entries:
	 */
	ret = victim_insert_hit_entries(victim, pcm);
	if (ret)
		return ERR_PTR(-ENOMEM);

	/*
	 * Make sure all updates can be seen by other CPUs
	 * before counter is updated. Others rely on the
	 * quick counter checking.
	 */
	smp_wmb();
	pcache_set_victim_inc(pset);

	return victim;
}

void victim_finish_insert(struct pcache_victim_meta *victim)
{
	void *src, *dst;
	struct pcache_meta *pcm = victim->pcm;

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);
	PCACHE_BUG_ON_VICTIM(!VictimAllocated(victim) ||
			      VictimHasdata(victim) ||
			      VictimWriteback(victim), victim);

	/*
	 * Copy the pcache line to victim cache
	 * The pcache line was unmapped and no changes
	 * would be made during memcpy.
	 */
	src = pcache_meta_to_kva(pcm);
	dst = pcache_victim_to_kva(victim);
	memcpy(dst, src, PCACHE_LINE_SIZE);

	smp_wmb();
	victim->pcm = NULL;
	SetVictimHasdata(victim);

	/*
	 * Submit flush job to worker thread
	 * Don't wait for the slow flush.
	 */
	victim_submit_flush_nowait(victim);
}

static inline void wait_victim_has_data(struct pcache_victim_meta *victim)
{
	unsigned long wait_start = jiffies;

	smp_rmb();
	while (unlikely(!VictimHasdata(victim))) {
		cpu_relax();

		/* Panic if it happens */
		if (unlikely(time_after(jiffies, wait_start + 5 * HZ)))
			panic("where is the victim finish insertion?");
	}
}

static int
__victim_fill_pcache(unsigned long address, unsigned long flags,
		     struct pcache_meta *pcm, void *_victim)
{
	struct pcache_victim_meta *victim = _victim;
	struct pcache_set *pset;
	void *victim_cache, *pcache;

	pset = pcache_meta_to_pcache_set(pcm);
	victim_cache = pcache_victim_to_kva(victim);
	pcache = pcache_meta_to_kva(pcm);

	wait_victim_has_data(victim);
	memcpy(pcache, victim_cache, PCACHE_LINE_SIZE);

	return 0;
}

/*
 * This function will fill the pcache line from victim cache.
 * If this fails, caller needs to fallback to remote memory.
 *
 * Return 0 on success, otherwise on VM_FAULT_XXX flags
 */
static inline int
victim_fill_pcache(struct mm_struct *mm, unsigned long address,
		   pte_t *page_table, pmd_t *pmd, unsigned long flags,
		   struct pcache_victim_meta *victim)
{
	return common_do_fill_page(mm, address, page_table, pmd, flags,
			__victim_fill_pcache, victim);
}

/* Return 0 on success */
int victim_try_fill_pcache(struct mm_struct *mm, unsigned long address,
			   pte_t *page_table, pmd_t *pmd,
			   unsigned long flags)
{
	struct pcache_victim_meta *victim;
	int index, ret = -1;

	for_each_victim(victim, index) {
		if (!VictimAllocated(victim))
			continue;

		if (victim_check_hit_entry(victim, address, current)) {
			ret = victim_fill_pcache(mm, address, page_table,
						 pmd, flags, victim);
			break;
		}
	}
	return ret;
}

static void __init pcache_init_victim_cache_meta_map(void)
{
	int i;

	/* Initialize each victim meta */
	for (i = 0; i < VICTIM_NR_ENTRIES; i++) {
		struct pcache_victim_meta *v;

		v = pcache_victim_meta_map + i;

		v->flags = 0;
		v->pcm = NULL;
		spin_lock_init(&v->lock);
		INIT_LIST_HEAD(&v->hits);
	}
}

/*
 * Allocate victim metadata and cache lines
 * This function is called during early boot, both buddy allocator
 * and slab are not avaiable. Use memblock instead.
 */
void __init victim_cache_init(void)
{
	u64 size;

	/* allocate the victim cache lines */
	size = VICTIM_NR_ENTRIES * PCACHE_LINE_SIZE;
	pcache_victim_data_map = memblock_virt_alloc(size, PAGE_SIZE);
	if (!pcache_victim_data_map)
		panic("Unable to allocate victim data map!");
	memset(pcache_victim_data_map, 0, size);

	/* allocate the victim cache meta map */
	size = VICTIM_NR_ENTRIES * sizeof(struct pcache_victim_meta);
	pcache_victim_meta_map = memblock_virt_alloc(size, PAGE_SIZE);
	if (!pcache_victim_meta_map)
		panic("Unable to allocate victim meta map!");

	pcache_init_victim_cache_meta_map();
}
