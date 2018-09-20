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
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/syscalls.h>
#include <lego/random.h>
#include <lego/jiffies.h>
#include <lego/profile.h>
#include <lego/memblock.h>
#include <processor/pcache.h>
#include <processor/processor.h>

/*
 * Same as pcache_rmap_map, we use the same trick here.
 * Check comment there.
 */
static struct pset_eviction_entry *pset_eviction_entry_map;

static inline struct pset_eviction_entry *
index_to_pee(unsigned long index)
{
	return &pset_eviction_entry_map[index];
}

static inline struct pset_eviction_entry *
alloc_pset_eviction_entry(struct pcache_meta *pcm)
{
	struct pset_eviction_entry *pee;
	unsigned long index;

	index = __pcache_meta_index(pcm);
	pee = index_to_pee(index);

	if (unlikely(TestSetPeeUsed(pee))) {
		pee = kmalloc(sizeof(*pee), GFP_KERNEL);
		if (unlikely(!pee))
			goto out;

		SetPeeKmalloced(pee);
		inc_pcache_event(PCACHE_PEE_ALLOC_KMALLOC);
	}

	INIT_LIST_HEAD(&pee->next);
out:
	inc_pcache_event(PCACHE_PEE_ALLOC);
	return pee;
}

static inline void free_pset_eviction_entry(struct pset_eviction_entry *pee)
{
	if (unlikely(PeeKmalloced(pee))) {
		kfree(pee);
		inc_pcache_event(PCACHE_PEE_FREE_KMALLOC);
		goto out;
	}

	if (unlikely(!TestClearPeeUsed(pee)))
		BUG();
out:
	inc_pcache_event(PCACHE_PEE_FREE);
}

static inline void __pset_add_eviction_entry(struct pset_eviction_entry *new,
					     struct pcache_set *pset)
{
	list_add(&new->next, &pset->eviction_list);
	atomic_inc(&pset->nr_eviction_entries);
}

static inline void __pset_del_eviction_entry(struct pset_eviction_entry *p,
					     struct pcache_set *pset)
{
	list_del(&p->next);
	atomic_dec(&pset->nr_eviction_entries);
}

static inline void
pset_add_eviction_entry(struct pset_eviction_entry *new, struct pcache_set *pset)
{
	spin_lock(&pset->eviction_list_lock);
	__pset_add_eviction_entry(new, pset);
	spin_unlock(&pset->eviction_list_lock);
}

bool __pset_find_eviction(struct pcache_set *pset, unsigned long uvaddr,
			  struct task_struct *tsk)
{
	struct pset_eviction_entry *pos;
	bool found = false;

	uvaddr &= PAGE_MASK;

	spin_lock(&pset->eviction_list_lock);
	list_for_each_entry(pos, &pset->eviction_list, next) {
		if (uvaddr == pos->address &&
		   same_thread_group(tsk, pos->owner)) {
			found = true;

			inc_pcache_event(PCACHE_PSET_LIST_HIT);
			break;
		}
	}
	spin_unlock(&pset->eviction_list_lock);

	return found;
}

static int pset_add_eviction_one(struct pcache_meta *pcm,
				 struct pcache_rmap *rmap, void *arg)
{
	int *nr_added = arg;
	struct pcache_set *pset = pcache_meta_to_pcache_set(pcm);
	struct pset_eviction_entry *new;

	new = alloc_pset_eviction_entry(pcm);
	if (unlikely(!new)) {
		WARN_ON_ONCE(1);
		return PCACHE_RMAP_FAILED;
	}

	/* Already page aligned */
	new->address = rmap->address;
	new->owner = rmap->owner_process;
	new->pcm = pcm;

	/* Do the insetion */
	pset_add_eviction_entry(new, pset);

	(*nr_added)++;
	return PCACHE_RMAP_AGAIN;
}

/*
 * Add pcm rmap information to pset's eviction list.
 * These entries will be looked up upon pcache fault time.
 *
 * Return number of entries added.
 */
static int pset_add_eviction(struct pcache_set *pset, struct pcache_meta *pcm)
{
	int nr_added = 0;
	struct rmap_walk_control rwc = {
		.arg = &nr_added,
		.rmap_one = pset_add_eviction_one,
	};

	/*
	 * This pcm was already locked and cannot be unmapped
	 * in the middle. Check comment in top function.
	 */
	BUG_ON(!pcache_mapped(pcm));

	rmap_walk(pcm, &rwc);
	return nr_added;
}

static void pset_remove_eviction(struct pcache_set *pset, struct pcache_meta *pcm,
				 int nr_added)
{
	struct pset_eviction_entry *pos;

	spin_lock(&pset->eviction_list_lock);
	list_for_each_entry(pos, &pset->eviction_list, next) {
		if (pos->pcm == pcm) {
			__pset_del_eviction_entry(pos, pset);
			free_pset_eviction_entry(pos);
			nr_added--;
		}
	}
	spin_unlock(&pset->eviction_list_lock);

	BUG_ON(nr_added);
}

DEFINE_PROFILE_POINT(evict_line_perset_unmap)
DEFINE_PROFILE_POINT(evict_line_perset_flush)

int evict_line_perset_list(struct pcache_set *pset, struct pcache_meta *pcm)
{
	int nr_added;
	bool dirty;
	PROFILE_POINT_TIME(evict_line_perset_unmap)
	PROFILE_POINT_TIME(evict_line_perset_flush)

	/*
	 * Add entries to pset
	 * This has to be performed before we do unmap, thus concurrent
	 * pgfault can look up the eviction entries, and hold until we finished.
	 */
	nr_added = pset_add_eviction(pset, pcm);
	if (unlikely(!nr_added)) {
		dump_pset(pset);
		dump_pcache_meta(pcm, NULL);
		BUG();
	}

	/* 2.1) Remove unmap, but don't free rmap */
	PROFILE_START(evict_line_perset_unmap);
	dirty = pcache_try_to_unmap_reserve_check_dirty(pcm);
	inc_pcache_event_cond(PCACHE_CLFLUSH_CLEAN_SKIPPED, !dirty);
	PROFILE_LEAVE(evict_line_perset_unmap);

	/* Only flush lines that are dirty */
	if (dirty) {
		PROFILE_START(evict_line_perset_flush);
		pcache_flush_one(pcm);
		PROFILE_LEAVE(evict_line_perset_flush);
	}

	/* 2.2) free reserved rmap */
	pcache_free_reserved_rmap(pcm);

	/* 3) remove entries */
	pset_remove_eviction(pset, pcm, nr_added);

	return 0;
}

void __init alloc_pcache_perset_map(void)
{
	size_t size, total;

	size = sizeof(struct pset_eviction_entry);
	total = size * nr_cachelines;

	pset_eviction_entry_map = memblock_virt_alloc(total, PAGE_SIZE);
	if (!pset_eviction_entry_map)
		panic("Unable to allocate pset_eviction_entry_map!");

	pr_info("%s(): eviction entry size: %zu B, total reserved: %zu B, at %p\n",
		__func__, size, total, pset_eviction_entry_map);
}
