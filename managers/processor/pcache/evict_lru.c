/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/wait.h>
#include <lego/slab.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>
#include <processor/pcache.h>
#include <processor/processor.h>

static inline bool pset_has_free_lines(struct pcache_set *pset)
{
	if (pset_nr_lru(pset) < PCACHE_ASSOCIATIVITY)
		return true;
	return false;
}

static inline void lru_put_pcache(struct pcache_meta *pcm, struct pcache_set *pset)
{
	/*
	 * This can happen as follows:
	 *   CPU0           CPU1                    pcache_ref after
	 *   .              .                       (ref=1)
	 *   .              lru_get_pcache          (ref=2)
	 *   put_pcache     .                       (ref=1)
	 *   .              put_pcache_testzero     (ref=0) Bingo!
	 *
	 * We enter with pset->lru_lock acquired.
	 * Thus we need to free it manually.
	 */
	if (unlikely(put_pcache_testzero(pcm))) {
		__del_from_lru_list(pcm, pset);
		__put_pcache_nolru(pcm);
	}
}

/* Return 1 if it was already 0, otherwise we inc the ref */
static inline int lru_get_pcache(struct pcache_meta *pcm)
{
	/*
	 * This can happen as follows:
	 *   CPU0                          CPU1
	 *   put_pcache()                  .
	 *   __put_pcache() ref=0          .
	 *   detach_from_lru()             sweep_pset_lru()/evict_find_line_lru()
	 *     spin_lock(&pset->lru_lock)  .
	 *     .. (spinning)               .
	 *     .. (spinning)               get_pcache_unless_zero() Bingo!
	 *
	 * pcache in LRU only has refcount 1, thus there is a small time
	 * frame where here we can see a pcache in a ref=0 state. But this
	 * is okay cause the above CPUs are synced by the lru_lock.
	 * We can proceed after we are sure this pcache is not being freed.
	 */
	return !get_pcache_unless_zero(pcm);
}

/*
 * This function is similar to some part of shrink_page_list(). 
 * The returned pcache is Locked, Reclaim, ref inc'ed 1 by us.
 */
struct pcache_meta *evict_find_line_lru(struct pcache_set *pset)
{
	struct pcache_meta *pcm;

	spin_lock(&pset->lru_lock);

	if (pset_has_free_lines(pset)) {
		pcm = ERR_PTR(-EAGAIN);
		goto unlock_lru;
	}

	list_for_each_entry_reverse(pcm, &pset->lru_list, lru) {
		PCACHE_BUG_ON_PCM(PcacheReclaim(pcm), pcm);

		/*
		 * Someone else freed at the same time
		 * Counter is updated within lru_lock, but we are holding it.
		 * Hence here we release the lock and tell caller retry directly
		 */
		if (unlikely(lru_get_pcache(pcm))) {
			pcm = ERR_PTR(-EAGAIN);
			goto unlock_lru;
		}

		/*
		 * This means pcache is within common_do_fill_page(),
		 * before pte and rmap are both setup.
		 * Do not race with normal pgfault code
		 */
		if (unlikely(!PcacheValid(pcm)))
			goto put_pcache;

		if (!trylock_pcache(pcm))
			goto put_pcache;

		if (PcacheWriteback(pcm))
			goto unlock_pcache;

		/*
		 * 1 for original allocation
		 * 1 for lru_get_pcache above
		 * Otherwise, it is used by others.
		 *
		 * XXX:
		 * This part need more attention.
		 * Currently we only have pcache_alloc/put, and eviction running.
		 * If later on, we add code such as exit_mmap(), chkpoint_flush(),
		 * those code has to be written with caution, esp. the op sequence
		 * of lock, get/put, flag_set etc.
		 */
		if (unlikely(pcache_ref_count(pcm) > 2))
			goto unlock_pcache;

		/*
		 * Yeah! We have a candidate that is:
		 * 0) Valid, mapped to user pgtable
		 * 1) locked by us
		 * 2) not under writeback
		 * 3) not used by others
		 *
		 * Remove it from LRU list, and set Reclaim
		 */
		__del_from_lru_list(pcm, pset);
		SetPcacheReclaim(pcm);
		goto unlock_lru;

unlock_pcache:
		unlock_pcache(pcm);
put_pcache:
		lru_put_pcache(pcm, pset);

		/*
		 * Previous lru_put_pcache() *may* free a line
		 * Someone else *may* free in the middle
		 */
		if (pset_has_free_lines(pset)) {
			pcm = ERR_PTR(-EAGAIN);
			goto unlock_lru;
		}
	}

unlock_lru:
	spin_unlock(&pset->lru_lock);

	return pcm;
}

/*
 * This function determines how "aggressive" the sweep is.
 * It is aggressive if whole LRU list is scanned, cause scan is not free
 */
static inline int get_sweep_count(struct pcache_set *pset)
{
	return pset_nr_lru(pset);
}

void sweep_pset_lru(struct pcache_set *pset)
{
	struct pcache_meta *pcm, *n;
	int nr_to_sweep;

	spin_lock(&pset->lru_lock);

	if (list_empty(&pset->lru_list))
		goto unlock;

	nr_to_sweep = get_sweep_count(pset);

	list_for_each_entry_safe(pcm, n, &pset->lru_list, lru) {
		PCACHE_BUG_ON_PCM(PcacheReclaim(pcm), pcm);

		if (unlikely(lru_get_pcache(pcm)))
			goto check_next;

		/*
		 * This means pcache is within common_do_fill_page(),
		 * before pte and rmap are both setup.
		 * Do not race with normal pgfault code
		 */
		if (unlikely(!PcacheValid(pcm)))
			goto put_pcache;

		/* Do not race with other normal operations. */
		if (!trylock_pcache(pcm))
			goto put_pcache;

		/* pcache can be unmaped just before we lock it */
		if (!pcache_mapped(pcm))
			goto unlock_pcache;

		/*
		 * Check PTEs
		 * If it has not been used for some time, move it to tail.
		 * Eviction will scan reversely.
		 */
		if (!pcache_referenced(pcm))
			list_move_tail(&pcm->lru, &pset->lru_list);

unlock_pcache:
		unlock_pcache(pcm);
put_pcache:
		lru_put_pcache(pcm, pset);
check_next:
		nr_to_sweep--;
		if (nr_to_sweep <= 0)
			break;
	}

unlock:
	spin_unlock(&pset->lru_lock);
}
