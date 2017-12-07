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
	panic("todo");
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

static struct pcache_victim_hit_entry *
alloc_victim_hit_entry(void)
{
	struct pcache_victim_hit_entry *entry;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (entry) {
		INIT_LIST_HEAD(&entry->next);
	}
	return entry;
}

static int victim_insert_rmap_one(struct pcache_meta *pcm,
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
victim_insert_rmap(struct pcache_victim_meta *victim, struct pcache_meta *pcm)
{
	struct rmap_walk_control rwc = {
		.arg = victim,
		.rmap_one = victim_insert_rmap_one,
	};

	rmap_walk(pcm, &rwc);

	return 0;
}

struct pcache_victim_meta *
victim_prepare_insert(struct pcache_set *pset, struct pcache_meta *pcm)
{
	struct pcache_victim_meta *victim;
	int ret;

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);

	victim = victim_alloc();
	if (!victim)
		return ERR_PTR(-ENOMEM);

	/* For two-step insertion */
	victim->pcm = pcm;

	ret = victim_insert_rmap(victim, pcm);
	if (ret)
		return ERR_PTR(-ENOMEM);

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

	victim->pcm = NULL;
	SetVictimHasdata(victim);

	/*
	 * Submit flush job to worker thread
	 * Don't wait for the slow flush.
	 */
	victim_submit_flush_nowait(victim);
}

/*
 * Check if @address associated with current address space
 * is cached in victim cache.
 */
int victim_check_hits(unsigned long address)
{
	return 0;
}

struct victim_flush_info {
	struct pcache_victim_meta *victim;
	struct completion done;
	bool wait;
	struct list_head list;
};

static DEFINE_SPINLOCK(victim_flush_lock);
static LIST_HEAD(victim_flush_list);
static struct task_struct *victim_flush_thread;

int victim_submit_flush(struct pcache_victim_meta *victim, bool wait)
{
	struct victim_flush_info *info;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;
	info->victim = victim;
	info->wait = wait;
	if (unlikely(wait))
		init_completion(&info->done);

	spin_lock(&victim_flush_lock);
	list_add_tail(&info->list, &victim_flush_list);
	spin_unlock(&victim_flush_lock);

	/* flush thread will free info */
	wake_up_process(victim_flush_thread);
	if (unlikely(wait))
		wait_for_completion(&info->done);
	return 0;
}

static int victim_flush_one(struct pcache_victim_meta *victim)
{
	void *cache_kva;
	int nr_flushed = 0;

	cache_kva = pcache_victim_to_kva(victim);
	spin_lock(&victim->lock);
	while (!list_empty(&victim->hits)) {
		struct pcache_victim_hit_entry *hit;
		int ret;

		hit = list_entry(victim->hits.next,
				struct pcache_victim_hit_entry, next);
		list_del_init(&hit->next);
		spin_unlock(&victim->lock);

		ret = clflush_one(hit->owner, hit->address, cache_kva);
		if (likely(!ret))
			nr_flushed++;

		spin_lock(&victim->lock);
	}
	spin_unlock(&victim->lock);

	return nr_flushed;
}

static void __victim_flush_func(struct victim_flush_info *info)
{
	bool wait = info->wait;
	struct completion *done = &info->done;
	struct pcache_victim_meta *victim = info->victim;

	SetVictimWriteback(victim);
	victim_flush_one(victim);
	ClearVictimWriteback(victim);

	if (unlikely(wait))
		complete(done);
	kfree(info);
}

static int victim_flush_func(void *unused)
{
	set_cpus_allowed_ptr(current, cpu_active_mask);

	for (;;) {
		/* Sleep until someone wakes me up before september ends */
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (list_empty(&victim_flush_list))
			schedule();
		__set_current_state(TASK_RUNNING);

		spin_lock(&victim_flush_lock);
		while (!list_empty(&victim_flush_list)) {
			struct victim_flush_info *info;

			info = list_entry(victim_flush_list.next,
					  struct victim_flush_info, list);
			list_del_init(&info->list);
			spin_unlock(&victim_flush_lock);

			__victim_flush_func(info);

			spin_lock(&victim_flush_lock);
		}
		spin_unlock(&victim_flush_lock);
	}
	return 0;
}

/* Has to be called after kthreadd is running */
void __init victim_cache_post_init(void)
{
	victim_flush_thread = kthread_run(victim_flush_func, NULL, "victimd");
	if (IS_ERR(victim_flush_thread))
		panic("Fail to create victim flush thread!");
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
