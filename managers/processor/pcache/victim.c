/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Our Victim Cache Friend
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

bool __pset_find_eviction(unsigned long uvaddr, struct task_struct *tsk)
{
	struct pcache_set *pset;
	struct pset_eviction_entry *pos;
	bool found = false;

	pset = user_vaddr_to_pcache_set(uvaddr);
	uvaddr &= PAGE_MASK;

	spin_lock(&pset->lock);
	list_for_each_entry(pos, &pset->eviction_list, next) {
		if (uvaddr == pos->address &&
		   tsk->group_leader == pos->owner->group_leader) {
			found = true;
			break;
		}
	}
	spin_unlock(&pset->lock);

	return found;
}

static int pset_add_eviction_one(struct pcache_meta *pcm,
				 struct pcache_rmap *rmap, void *arg)
{
	int *nr_added = arg;
	struct pcache_set *pset = pcache_meta_to_pcache_set(pcm);
	struct pset_eviction_entry *new;

	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return PCACHE_RMAP_FAILED;

	new->address = rmap->address & PAGE_MASK;
	new->owner = rmap->owner;
	new->pcm = pcm;

	spin_lock(&pset->lock);
	list_add(&new->next, &pset->eviction_list);
	__set_bit(pcache_set_to_set_index(pset), pcache_set_eviction_bitmap);
	spin_unlock(&pset->lock);

	(*nr_added)++;
	return PCACHE_RMAP_AGAIN;
}

int pset_add_eviction(struct pcache_set *pset, struct pcache_meta *pcm)
{
	int nr_added;
	struct rmap_walk_control rwc = {
		.arg = &nr_added,
		.rmap_one = pset_add_eviction_one,
	};

	if (!pcache_mapped(pcm))
		return 0;
	rmap_walk(pcm, &rwc);
	return nr_added;
}

void pset_remove_eviction(struct pcache_set *pset, struct pcache_meta *pcm)
{
	struct pset_eviction_entry *pos, *keeper;

	spin_lock(&pset->lock);
	list_for_each_entry_safe(pos, keeper, &pset->eviction_list, next) {
		if (pos->pcm == pcm) {
			list_del(&pos->next);
			kfree(pos);
		}
	}

	if (list_empty(&pset->eviction_list))
		clear_bit(pcache_set_to_set_index(pset),
			  pcache_set_eviction_bitmap);
	spin_unlock(&pset->lock);
}

void add_victim_meta(struct pcache_set *pset, struct pcache_meta *pcm)
{

}

void add_victim_data(struct pcache_meta *pcm)
{

}
