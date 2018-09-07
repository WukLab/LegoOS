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
#include <processor/pcache.h>
#include <processor/processor.h>

static inline struct pset_eviction_entry *
alloc_pset_eviction_entry(void)
{
	struct pset_eviction_entry *entry;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (entry) {
		INIT_LIST_HEAD(&entry->next);
	}
	return entry;
}

static inline void free_pset_eviction_entry(struct pset_eviction_entry *p)
{
	kfree(p);
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

	new = alloc_pset_eviction_entry();
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

DEFINE_PROFILE_POINT(evict_line_perset_add)
DEFINE_PROFILE_POINT(evict_line_perset_unmap)
DEFINE_PROFILE_POINT(evict_line_perset_flush)
DEFINE_PROFILE_POINT(evict_line_perset_remove)

int evict_line_perset_list(struct pcache_set *pset, struct pcache_meta *pcm)
{
	int nr_added;
	PROFILE_POINT_TIME(evict_line_perset_add)
	PROFILE_POINT_TIME(evict_line_perset_unmap)
	PROFILE_POINT_TIME(evict_line_perset_flush)
	PROFILE_POINT_TIME(evict_line_perset_remove)

	/*
	 * Add entries to pset
	 * This has to be performed before we do unmap, thus concurrent
	 * pgfault can look up the eviction entries, and hold until we finished.
	 */
	PROFILE_START(evict_line_perset_add);
	nr_added = pset_add_eviction(pset, pcm);
	if (unlikely(!nr_added)) {
		dump_pset(pset);
		dump_pcache_meta(pcm, NULL);
		BUG();
	}
	PROFILE_LEAVE(evict_line_perset_add);

	/* 2.1) Remove unmap, but don't free rmap */
	PROFILE_START(evict_line_perset_unmap);
	pcache_try_to_unmap_reserve(pcm);
	PROFILE_LEAVE(evict_line_perset_unmap);

	PROFILE_START(evict_line_perset_flush);
	pcache_flush_one(pcm);
	PROFILE_LEAVE(evict_line_perset_flush);

	/* 2.2) free reserved rmap */
	pcache_free_reserved_rmap(pcm);

	/* 3) remove entries */
	PROFILE_START(evict_line_perset_remove);
	pset_remove_eviction(pset, pcm, nr_added);
	PROFILE_LEAVE(evict_line_perset_remove);

	return 0;
}
