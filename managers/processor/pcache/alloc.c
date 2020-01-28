/*
 * Copyright (c) 2016-2020 Wuklab, Purdue University. All rights reserved.
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
#include <lego/jiffies.h>
#include <lego/profile.h>
#include <processor/pcache.h>
#include <processor/processor.h>

#include "piggyback.h"

DEFINE_PER_CPU(struct pcache_meta *, piggybacker);

/**
 * sysctl_pcache_alloc_timeout_sec
 *
 * The maximum time a pcache_alloc can take due to slowpath eviction.
 */
unsigned long sysctl_pcache_alloc_timeout_sec __read_mostly = 30;

static void bad_pcache(struct pcache_meta *pcm,
		       const char *reason, unsigned long bad_flags)
{
	static bool bad_pcache_printed = false;

	if (bad_pcache_printed)
		return;

	pr_alert("BUG: Bad pcache state in process [%s][pid:%d tgid: %d]\n",
		current->comm, current->pid, current->tgid);

	dump_pcache_meta(pcm, reason);

	bad_flags &= pcm->bits;
	if (bad_flags)
		pr_alert("bad because of flags: %#lx(%pGc)\n",\
			 bad_flags, &bad_flags);
	WARN_ON_ONCE(1);
	bad_pcache_printed = true;
	/* Leave bad fields for debug */
}

static void pcache_free_check_bad(struct pcache_meta *pcm)
{
	const char *bad_reason;
	unsigned long bad_flags;

	bad_reason = NULL;
	bad_flags = 0;

	if (unlikely(atomic_read(&pcm->mapcount) != 0))
		bad_reason = "nonzero mapcount";
	if (unlikely(pcache_ref_count(pcm) != 0))
		bad_reason = "nonzero _refcount";
	if (unlikely(pcm->bits & PCACHE_FLAGS_CHECK_AT_FREE)) {
		bad_reason = "PCACHE_FLAGS_CHECK_AT_FREE flag(s) set";
		bad_flags = PCACHE_FLAGS_CHECK_AT_FREE;
	}
	bad_pcache(pcm, bad_reason, bad_flags);
}

static inline bool pcache_expected_state(struct pcache_meta *pcm,
					 unsigned long check_flags)
{
	/* which implies p->rmap list is empty */
	if (unlikely(atomic_read(&pcm->mapcount) != 0))
		return false;

	if (unlikely(pcache_ref_count(pcm)))
		return false;

	/* Flags should not be set */
	if (unlikely(pcm->bits & check_flags))
		return false;

	return true;
}

static inline void pcache_free_check(struct pcache_meta *pcm)
{
	if (likely(pcache_expected_state(pcm, PCACHE_FLAGS_CHECK_AT_FREE)))
		return;
	pcache_free_check_bad(pcm);
}

static inline void
__enqueue_free_list_head(struct pcache_meta *pcm, struct pcache_set *pset)
{
	list_add(&pcm->free_list, &pset->free_head);
}

static inline struct pcache_meta *
__dequeue_free_list_head(struct pcache_set *pset)
{
        struct pcache_meta *pcm;

        pcm = list_first_entry(&pset->free_head, struct pcache_meta, free_list);
        list_del(&pcm->free_list);
        return pcm;
}

/*
 * This is the ultimate free function.
 * At the time of calling, @pcm has been removed from LRU list.
 * Upon finish, @pcm will be enqueued into free list.
 */
void __put_pcache_nolru(struct pcache_meta *pcm)
{
	struct pcache_set *pset;

	pcache_free_check(pcm);
	dec_pcache_used();

	/*
	 * This @pcm is pushed into per-cpu cached
	 * piggyback candidate. Skip enqueuing.
	 */
	if (PcachePiggybackCached(pcm))
		return;

	pset = pcache_meta_to_pcache_set(pcm);
	spin_lock(&pset->free_lock);
	__enqueue_free_list_head(pcm, pset);
	spin_unlock(&pset->free_lock);
}

/*
 * Called when refcount drops to 0, which means @pcm has no users anymore.
 * Free it, return it back to the free pool within the set @pcm belongs to.
 */
void __put_pcache(struct pcache_meta *pcm)
{
	detach_from_lru(pcm);
	__put_pcache_nolru(pcm);
}

static inline void pcache_reset_flags(struct pcache_meta *pcm)
{
	smp_store_mb(pcm->bits, 0);
}

static inline void prep_new_pcache_meta(struct pcache_meta *pcm)
{
	INIT_LIST_HEAD(&pcm->rmap);
	init_pcache_lru(pcm);

	/*
	 * _mapcount = 0
	 * _refcount = 1  for the caller
	 */
	pcache_mapcount_reset(pcm);
	init_pcache_ref_count(pcm);
}

static inline struct pcache_meta *
pcache_alloc_fastpath(struct pcache_set *pset)
{
	struct pcache_meta *pcm;

	pcm = get_per_cpu_piggybacker();
	if (pcm) {
		/* Also clear the Cached flag */
		pcache_reset_flags(pcm);
		SetPcachePiggyback(pcm);
		goto prep;
	}

	spin_lock(&pset->free_lock);
	if (list_empty(&pset->free_head)) {
		spin_unlock(&pset->free_lock);
		return NULL;
	}
	pcm = __dequeue_free_list_head(pset);
	spin_unlock(&pset->free_lock);

	pcache_reset_flags(pcm);
prep:
	prep_new_pcache_meta(pcm);
	add_to_lru_list(pcm, pset);
	inc_pcache_used();
	return pcm;
}

DEFINE_PROFILE_POINT(pcache_alloc)
DEFINE_PROFILE_POINT(pcache_alloc_evict)
DEFINE_PROFILE_POINT(pcache_alloc_fastpath)

/**
 * pcache_alloc
 * @address: user virtual address
 * @piggyback: if this is true, underlying pcache eviction routine will enable
 *             piggyback optimization. We only have one single caller is able
 *             to use this opt, which is pcache fault on remote.
 *
 * This function will try to allocate a cacheline from the set that @address
 * belongs to. On success, the returned @pcm has refcount 1, and mapcount 0.
 *
 * Profile Points:
 *
 *	pcache_alloc
 *	|- pcache_alloc_fastpath
 *	|- pcache_alloc_evict
 *	   |- pcache_alloc_evict_do_find
 *	   |- pcache_alloc_evict_do_evict
 */
struct pcache_meta *pcache_alloc(unsigned long address,
				 enum piggyback_options piggyback)
{
	struct pcache_set *pset;
	struct pcache_meta *pcm;
	enum evict_status ret;
	unsigned long alloc_start, timeout;
	PROFILE_POINT_TIME(pcache_alloc)
	PROFILE_POINT_TIME(pcache_alloc_evict)
	PROFILE_POINT_TIME(pcache_alloc_fastpath)

	PROFILE_START(pcache_alloc);

	alloc_start = jiffies;
	timeout = alloc_start + sysctl_pcache_alloc_timeout_sec * HZ;

	pset = user_vaddr_to_pcache_set(address);
	inc_pset_event(pset, PSET_ALLOC);

retry:
	/* Fastpath try to allocate one directly */
	PROFILE_START(pcache_alloc_fastpath);
	pcm = pcache_alloc_fastpath(pset);
	PROFILE_LEAVE(pcache_alloc_fastpath);
	if (likely(pcm)) {
		if (piggyback == DISABLE_PIGGYBACK && PcachePiggyback(pcm))
			BUG();
		PROFILE_LEAVE(pcache_alloc);
		return pcm;
	}

	PROFILE_START(pcache_alloc_evict);
	ret = pcache_evict_line(pset, address, piggyback);
	PROFILE_LEAVE(pcache_alloc_evict);
	switch (ret) {
	case PCACHE_EVICT_FAILURE_FIND:
	case PCACHE_EVICT_FAILURE_EVICT:
		return NULL;
	case PCACHE_EVICT_EAGAIN_FREEABLE:
	case PCACHE_EVICT_EAGAIN_CONCURRENT:
	case PCACHE_EVICT_SUCCEED:
		break;
	default:
		BUG();
	};

	if (likely(time_before(jiffies, timeout)))
		goto retry;

	/* Then we have a situation */
	pr_info("# CPU%d PID%d Abort pcache alloc (%ums) addr:%#lx pset:%lu\n",
		smp_processor_id(), current->pid,
		jiffies_to_msecs(jiffies - alloc_start),
		address, pcache_set_to_set_index(pset));
	return NULL;
}
