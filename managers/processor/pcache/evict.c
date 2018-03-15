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
#include <processor/pcache.h>
#include <processor/processor.h>

/**
 * evict_find_line
 * @pset: the pcache set in question
 *
 * This function will find a line to evict within a set.
 * The returned pcache line MUST be locked.
 */
static inline struct pcache_meta *
evict_find_line(struct pcache_set *pset)
{
#ifdef CONFIG_PCACHE_EVICT_RANDOM
	return evict_find_line_random(pset);
#elif defined(CONFIG_PCACHE_EVICT_FIFO)
	return evict_find_line_fifo(pset);
#elif defined(CONFIG_PCACHE_EVICT_LRU)
	return evict_find_line_lru(pset);
#endif
}

#ifdef CONFIG_PCACHE_EVICTION_PERSET_LIST
/* per set eviction status: for fast lookup */
unsigned long *pcache_set_eviction_bitmap __read_mostly;

bool __pset_find_eviction(unsigned long uvaddr, struct task_struct *tsk)
{
	struct pcache_set *pset;
	struct pset_eviction_entry *pos;
	bool found = false;

	pset = user_vaddr_to_pcache_set(uvaddr);
	uvaddr &= PAGE_MASK;

	spin_lock(&pset->eviction_list_lock);
	list_for_each_entry(pos, &pset->eviction_list, next) {
		if (uvaddr == pos->address &&
		   same_thread_group(tsk, pos->owner)) {
			found = true;
			break;
		}
	}
	spin_unlock(&pset->eviction_list_lock);

	return found;
}

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

static int pset_add_eviction_one(struct pcache_meta *pcm,
				 struct pcache_rmap *rmap, void *arg)
{
	int *nr_added = arg;
	struct pcache_set *pset = pcache_meta_to_pcache_set(pcm);
	struct pset_eviction_entry *new;

	new = alloc_pset_eviction_entry();
	if (!new)
		return PCACHE_RMAP_FAILED;

	new->address = rmap->address;
	new->owner = rmap->owner_process;
	new->pcm = pcm;

	spin_lock(&pset->eviction_list_lock);
	list_add(&new->next, &pset->eviction_list);
	__set_bit(pcache_set_to_set_index(pset), pcache_set_eviction_bitmap);
	spin_unlock(&pset->eviction_list_lock);

	(*nr_added)++;
	return PCACHE_RMAP_AGAIN;
}

static int pset_add_eviction(struct pcache_set *pset, struct pcache_meta *pcm)
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

static void pset_remove_eviction(struct pcache_set *pset, struct pcache_meta *pcm)
{
	struct pset_eviction_entry *pos, *keeper;

	spin_lock(&pset->eviction_list_lock);
	list_for_each_entry_safe(pos, keeper, &pset->eviction_list, next) {
		if (pos->pcm == pcm) {
			list_del(&pos->next);
			kfree(pos);
		}
	}

	if (list_empty(&pset->eviction_list))
		clear_bit(pcache_set_to_set_index(pset),
			  pcache_set_eviction_bitmap);
	spin_unlock(&pset->eviction_list_lock);
}

static inline int
evict_line_perset_list(struct pcache_set *pset, struct pcache_meta *pcm)
{
	/* 1) add entries to per set list */
	pset_add_eviction(pset, pcm);

	/* 2.1) Remove unmap, but don't free rmap */
	pcache_try_to_unmap_reserve(pcm);
	pcache_flush_one(pcm);
	/* 2.2) free reserved rmap */
	pcache_free_reserved_rmap(pcm);

	/* 3) remove entries */
	pset_remove_eviction(pset, pcm);

	return 0;
}
#endif /* CONFIG_PCACHE_EVICTION_PERSET_LIST */

#ifdef CONFIG_PCACHE_EVICTION_VICTIM
static inline int
evict_line_victim(struct pcache_set *pset, struct pcache_meta *pcm)
{
	struct pcache_victim_meta *victim;

	victim = victim_prepare_insert(pset, pcm);
	if (IS_ERR(victim))
		return PTR_ERR(victim);

	/*
	 * Make sure other cpus can see the above
	 * updates before we do the unmap operations.
	 */
	smp_wmb();
	pcache_try_to_unmap(pcm);

	victim_finish_insert(victim);

	return 0;
}
#endif

#ifdef CONFIG_PCACHE_EVICTION_WRITE_PROTECT
static inline int
evict_line_wrprotect(struct pcache_set *pset, struct pcache_meta *pcm)
{
	/* 1) write-protect from all threads */
	pcache_wrprotect(pcm);

	/* 2) Safely flush back */
	pcache_flush_one(pcm);

	/* 3) unmap all PTEs */
	pcache_try_to_unmap(pcm);

	return 0;
}
#endif

static inline int
evict_line(struct pcache_set *pset, struct pcache_meta *pcm)
{
#ifdef CONFIG_PCACHE_EVICTION_WRITE_PROTECT
	return evict_line_wrprotect(pset, pcm);
#elif defined(CONFIG_PCACHE_EVICTION_PERSET_LIST)
	return evict_line_perset_list(pset, pcm);
#elif defined(CONFIG_PCACHE_EVICTION_VICTIM)
	return evict_line_victim(pset, pcm);
#endif
}

/**
 * pcache_evict_line
 * @pset: the pcache set to find a line to evict
 * @address: the user virtual address who initalized this eviction
 *
 * 1)
 * This function will try to evict one cache line from @pset.
 * If succeed, the cache line will be flushed back to its backing memory.
 * This function can be called concurrently: the selection of cache line
 * is serialized by pset lock, the real eviction procedure can be overlapped.
 *
 * 2)
 * We clear pte and pcache in this sequence:
 * 	a) unmap pte
 * 	b) free pcache
 * This guarantees: if pgfault routines (pcache_do_wp_page) or some rmap walkers
 * use pte_to_pcache_meta() to get the corresponding pcm, and continues holding
 * the pte lock while doing something to this pcm, they are guaranteed this pcm
 * will not go away in the middle.
 *
 * Return 0 on success, otherwise on failures.
 */
int pcache_evict_line(struct pcache_set *pset, unsigned long address)
{
	struct pcache_meta *pcm;
	int nr_mapped;
	int ret;

	inc_pcache_event(PCACHE_EVICTION_TRIGGERED);

	/* Algorithm hook */
	pcm = evict_find_line(pset);
	if (IS_ERR_OR_NULL(pcm)) {
		if (likely(PTR_ERR(pcm) == -EAGAIN)) {
			inc_pcache_event(PCACHE_EVICTION_EAGAIN_FREEABLE);
			return PCACHE_EVICT_EAGAIN_FREEABLE;
		} else {
			inc_pcache_event(PCACHE_EVICTION_FAILURE_FIND);
			return PCACHE_EVICT_FAILURE_FIND;
		}
	}

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);
	PCACHE_BUG_ON_PCM(!PcacheReclaim(pcm), pcm);

	/* we locked, it can not be unmapped by others */
	nr_mapped = pcache_mapcount(pcm);
	BUG_ON(nr_mapped < 1);

	ret = evict_line(pset, pcm);
	if (ret) {
		/*
		 * Revert what algorithm has done:
		 * - Clear reclaim flag
		 * - add it back to lru list (update counter)
		 * - unlock
		 * - dec ref (may lead to free)
		 */
		ClearPcacheReclaim(pcm);
		add_to_lru_list(pcm, pset);
		unlock_pcache(pcm);
		put_pcache(pcm);

		inc_pcache_event(PCACHE_EVICTION_FAILURE_EVICT);
		return PCACHE_EVICT_FAILURE_EVICT;
	}

	/*
	 * After a successful eviction, @pcm has no rmap left
	 * which implies PcacheValid is cleared too.
	 */
	PCACHE_BUG_ON_PCM(pcache_mapped(pcm) || PcacheValid(pcm), pcm);

	/*
	 * Each rmap counts one refcount, plus the one grabbed
	 * during evict_find_line(), we should have (nr_mapped + 1)
	 * here if there are no any other users.
	 *
	 * Furthurmore, others can not go from munmap/mremap/wp to
	 * put_pcache() within pcache_zap_pte(), pcache_move_pte()
	 * or pcache_do_wp_page(). Thus the refcount must larger or
	 * equal to (nr_mapped + 1).
	 *
	 * But if there truly other users (refcount > nr_mapped + 1),
	 * then we should manually sub the refcount. The other users
	 * which are currently holding the ref, will free the pcache
	 * once it call put_pcache.
	 */
	PCACHE_BUG_ON_PCM(pcache_ref_count(pcm) < nr_mapped + 1, pcm);
	if (unlikely(!pcache_ref_freeze(pcm, nr_mapped + 1))) {
		if (unlikely(pcache_ref_sub_and_test(pcm, nr_mapped + 1))) {
			pr_info("BUG: pcm refcount, nr_mapped: %d\n", nr_mapped);
			dump_pcache_meta(pcm, "ref error");
			BUG();
		}

		ClearPcacheReclaim(pcm);
		add_to_lru_list(pcm, pset);
		unlock_pcache(pcm);

		inc_pcache_event(PCACHE_EVICTION_EAGAIN_CONCURRENT);
		return PCACHE_EVICT_EAGAIN_CONCURRENT;
	}

	/*
	 * Succeed: pcm is unmapped, and no other threads
	 * are using it. Simply free and return it to pset.
	 */
	__ClearPcacheReclaim(pcm);
	__ClearPcacheLocked(pcm);
	__put_pcache_nolru(pcm);

	inc_pset_event(pset, PSET_EVICTION);
	inc_pcache_event(PCACHE_EVICTION_SUCCEED);
	return PCACHE_EVICT_SUCCEED;
}
