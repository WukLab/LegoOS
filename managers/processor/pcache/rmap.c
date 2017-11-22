/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/syscalls.h>
#include <lego/ratelimit.h>
#include <lego/comp_processor.h>

#include <asm/io.h>
#include <asm/tlbflush.h>

#include <processor/include/pcache.h>

int pcache_add_rmap(struct pcache_meta *pcm, pte_t *page_table,
		    unsigned long address)
{
	struct pcache_rmap *rmap, *pos;
	struct pcache_set *pset;

	rmap = kmalloc(sizeof(*rmap), GFP_KERNEL);
	if (!rmap)
		return -ENOMEM;
	rmap->page_table = page_table;
	rmap->address = address;
	rmap->owner = current;

	/*
	 * Use the lock of pcache set to protect
	 * all ways rmap operations:
	 */
	pset = pcache_meta_to_pcache_set(pcm);
	spin_lock(&pset->lock);
	if (likely(list_empty(&pcm->rmap)))
		goto add;

	list_for_each_entry(pos, &pcm->rmap, next)
		BUG_ON(pos->page_table == page_table);

add:
	list_add(&rmap->next, &pcm->rmap);
	atomic_inc(&pcm->mapcount);
	spin_unlock(&pset->lock);
	return 0;
}

static __always_inline pte_t *
rmap_get_checked_pte(struct pcache_meta *pcm, struct pcache_rmap *rmap)
{
	/* TODO: Safety check if the @mm truly has this pte
	 * and if the pfn in pte and this page_table matches */
	return rmap->page_table;
}

static inline void
pcache_paronoid_unmap_check(pte_t pte, struct pcache_meta *pcm,
			    struct pcache_rmap *rmap)
{
	unsigned long pcm_pfn, pgtable_pfn;

	pcm_pfn = pcache_meta_to_pfn(pcm);
	pgtable_pfn = pte_pfn(pte);
	if (unlikely(pcm_pfn != pgtable_pfn)) {
		pr_err("owner: %u pcm_pfn: %#lx, pte_pfn: %#lx\n",
			rmap->owner->pid, pcm_pfn, pgtable_pfn);
		BUG();
	}
}

static void __unmap_dump(struct pcache_rmap *rmap)
{
	unsigned long va = rmap->address;
	struct task_struct *owner = rmap->owner;
	pte_t pte, *ptep = rmap->page_table;

	pte = *ptep;
	pr_info("%s() owner: %u, va: %#lx pfn: %#lx dirty: %d\n",
		FUNC, owner->pid, va, pte_pfn(pte), pte_dirty(pte)? 1:0);
}

static int pcache_try_to_unmap_one(struct pcache_meta *pcm,
				   struct pcache_rmap *rmap, void *arg)
{
	int ret = PCACHE_RMAP_AGAIN;
	pte_t *pte;
	pte_t pteval;

	pte = rmap_get_checked_pte(pcm, rmap);
	if (!pte)
		goto out;
	__unmap_dump(rmap);

	pteval = ptep_get_and_clear(0, pte);
	pcache_paronoid_unmap_check(pteval, pcm, rmap);

	if (pte_present(pteval))
		flush_tlb_mm_range(rmap->owner->mm,
				   rmap->address,
				   rmap->address + PAGE_SIZE -1);

	list_del(&rmap->next);
	kfree(rmap);
	atomic_dec(&pcm->mapcount);

out:
	return ret;
}

static int pcache_mapcount_is_zero(struct pcache_meta *pcm)
{
	return !pcache_mapcount(pcm);
}

/**
 * pcache_try_to_unmap
 * @pcm: the pcache to get unmapped
 *
 * Tries to remove all the page table entries which are mapping this
 * pcache, used in the pageout path.
 *
 * Return:
 *	PCACHE_RMAP_SUCCEED	- we succeeded in removing all mappings
 *	PCACHE_RMAP_AGAIN	- we missed a mapping, try again later
 */
int pcache_try_to_unmap(struct pcache_meta *pcm)
{
	int ret;

	struct rmap_walk_control rwc = {
		.rmap_one = pcache_try_to_unmap_one,
		.done = pcache_mapcount_is_zero,
	};

	ret = rmap_walk(pcm, &rwc);
	if (!pcache_mapcount(pcm))
		ret = PCACHE_RMAP_SUCCEED;
	return ret;
}

int rmap_walk(struct pcache_meta *pcm, struct rmap_walk_control *rwc)
{
	struct pcache_rmap *rmap, *keeper;
	struct pcache_set *pset;
	int ret = PCACHE_RMAP_AGAIN;

	pset = pcache_meta_to_pcache_set(pcm);

	/* rmap addition is protected by the pset lock */
	spin_lock(&pset->lock);
	list_for_each_entry_safe(rmap, keeper, &pcm->rmap, next) {
		ret = rwc->rmap_one(pcm, rmap, rwc->arg);
		if (ret != PCACHE_RMAP_AGAIN)
			break;

		if (rwc->done && rwc->done(pcm))
			break;
	}
	spin_unlock(&pset->lock);

	return ret;
}
