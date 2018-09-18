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
#include <lego/delay.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>
#include <lego/profile.h>
#include <processor/pcache.h>
#include <processor/processor.h>

/*
 * New pcache lines are inserted at the head
 * Eviction scan from the tail reversely
 * Sweep will move unused pcache to tail
 */

static inline bool pset_has_free_lines(struct pcache_set *pset)
{
	if (pset_nr_lru(pset) < PCACHE_ASSOCIATIVITY)
		return true;
	return false;
}

/* Return 1 if we freed it, otherwise return 0 */
static inline int lru_put_pcache(struct pcache_meta *pcm, struct pcache_set *pset)
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
		return 1;
	}
	return 0;
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
	bool found = false;

	/*
	 * We used to check if @pset has free lines in the middle
	 * of the loop. We no longer do that anymore. The reason is
	 * we want to leave cushion for each cpu. We don't want
	 * CPUs to contend for one just-freed-line. Instead, we
	 * want each CPU do its eviction and allocation on its own.
	 */
	spin_lock(&pset->lru_lock);
	list_for_each_entry_reverse(pcm, &pset->lru_list, lru) {
		PCACHE_BUG_ON_PCM(PcacheReclaim(pcm), pcm);

		/*
		 * Someone else freed at the same time
		 * Counter is updated within lru_lock, but we are holding it.
		 * Hence here we release the lock and tell caller retry directly
		 */
		if (unlikely(lru_get_pcache(pcm)))
			goto unlock_lru;

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
		found = true;
		__del_from_lru_list(pcm, pset);
		SetPcacheReclaim(pcm);
		goto unlock_lru;

unlock_pcache:
		unlock_pcache(pcm);
put_pcache:
		lru_put_pcache(pcm, pset);
	}

unlock_lru:
	spin_unlock(&pset->lru_lock);

	if (!found)
		pcm = ERR_PTR(-EAGAIN);
	return pcm;
}

#ifdef CONFIG_PCACHE_EVICT_GENERIC_SWEEP
/*
 * This function determines how "aggressive" the sweep is.
 * It is aggressive if whole LRU list is scanned, cause scan is not free
 */
static inline void
get_sweep_count(struct pcache_set *pset, int *nr_to_sweep, int *nr_goal)
{
	int threshold;

	/*
	 * How many pcm we want to move during this sweep?
	 * Maybe 1 or 2 is enough?
	 */
	*nr_goal = 1;

	/*
	 * If concurrent evict happens, then at least one pcache
	 * will be removed from the list. Minus 1 here means if
	 * only one evict happen, then we sweep anyway. But if multiple
	 * evicti happen, we abort sweep to reduce lock contention.
	 */
	threshold = PCACHE_ASSOCIATIVITY - 1;

	if (likely(pset_nr_lru(pset) < threshold)) {
		*nr_to_sweep = 0;
		return;
	}

	/*
	 * XXX:
	 * To be or not to be? How many to sweep is a hard question.
	 * sweep half? Just a random guess now.
	 */
	*nr_to_sweep = PCACHE_ASSOCIATIVITY/4;
}

/*
 * References
 * https://linux-mm.org/PageReplacementDesign
 * https://linux-mm.org/PageReplacementRequirements
 */
static void sweep_pset(struct pcache_set *pset)
{
	struct pcache_meta *pcm, *n;
	int nr_to_sweep, nr_goal;

	get_sweep_count(pset, &nr_to_sweep, &nr_goal);
	if (!nr_to_sweep || !nr_goal)
		return;

	if (!spin_trylock(&pset->lru_lock))
		return;

	list_for_each_entry_safe(pcm, n, &pset->lru_list, lru) {
		int pte_referenced, pte_contention;

		PCACHE_BUG_ON_PCM(PcacheReclaim(pcm), pcm);

		/*
		 * If someone is trying to free the pcm
		 * we don't want to block it.
		 */
		if (unlikely(lru_get_pcache(pcm)))
			break;

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
		pcache_referenced_trylock(pcm, &pte_referenced, &pte_contention);

		if (!pte_contention && !pte_referenced) {
			nr_goal--;
			list_move_tail(&pcm->lru, &pset->lru_list);
			inc_pcache_event(PCACHE_SWEEP_NR_MOVED_PCM);
		}

unlock_pcache:
		unlock_pcache(pcm);
put_pcache:
		/*
		 * Someone just tried to free it
		 * We should not block it
		 */
		if (lru_put_pcache(pcm, pset))
			break;

		/*
		 * We have achieved our goal yet?
		 */
		if (!nr_goal)
			break;

		/*
		 * Stop the checking if reaches the requirement.
		 * Do not attempt to walk through whole list.
		 */
		nr_to_sweep--;
		if (nr_to_sweep <= 0)
			break;

		/*
		 * Pset has eviction request.
		 * We should release the lock
		 */
		if (PsetEvicting(pset))
			break;
	}
	spin_unlock(&pset->lru_lock);
}

/*
 * Profile the time to sweep the whole cache,
 * and the time to sweep each set in average.
 */
DEFINE_PROFILE_POINT(evict_lru_sweep)
DEFINE_PROFILE_POINT(evict_lru_sweep_set)

int sysctl_pcache_evict_interval_msec __read_mostly = CONFIG_PCACHE_EVICT_GENERIC_SWEEP_INTERVAL_MSEC;

void kevict_sweepd_lru(void)
{
	int setidx;
	struct pcache_set *pset;
	PROFILE_POINT_TIME(evict_lru_sweep)
	PROFILE_POINT_TIME(evict_lru_sweep_set)

	while (1) {
		PROFILE_START(evict_lru_sweep);
		pcache_for_each_set(pset, setidx) {
			/*
			 * Don't race with normal eviction loops
			 * This bit will be set during pcache_evict_line.
			 */
			if (PsetEvicting(pset))
				continue;

			/*
			 * We skip the set, as long as it is not completely full
			 * (==PCACHE_ASSOCIATIVITY),
			 */
			if ((pset_nr_lru(pset) < PCACHE_ASSOCIATIVITY))
				continue;

			__SetPsetSweeping(pset);
			PROFILE_START(evict_lru_sweep_set);
			sweep_pset(pset);
			PROFILE_LEAVE(evict_lru_sweep_set);
			__ClearPsetSweeping(pset);

			inc_pcache_event(PCACHE_SWEEP_NR_PSET);
		}
		PROFILE_LEAVE(evict_lru_sweep);
		inc_pcache_event(PCACHE_SWEEP_RUN);

		/*
		 * Well.. just to stop being an asshole to other customers.
		 * The more we sleep/delay, probably the nicer we are. ;-)
		 */
		mdelay(sysctl_pcache_evict_interval_msec);
	}
}
#endif /* CONFIG_PCACHE_EVICT_GENERIC_SWEEP */
