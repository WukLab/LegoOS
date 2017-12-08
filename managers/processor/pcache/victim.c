/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * A)
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
 * |      ..                                   |    pgfault                   |
 * |      ..                                   |    ->check victim            |
 * |      ..                                   |    ->wait copy finished      |
 * |      ..                                   |    ..                        |
 * |    - finish copy from pcache to victim    |    ..                        |
 * |      ..                                   |    ->copy from victim->pcache|
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

/*
 * B)
 * victim->flags
 *
 *    Allocated:
 * 	Set when victim is used, clear when free.
 * 	Simply used to guide victim allocation/free.
 *
 *    Hasdata:
 * 	Set when the second step of insertion finished.
 *
 *    Writeback:
 * 	Set *while* the victim is being flushed back to memory.
 * 	Set only by victim flush routine.
 *
 *    Flushed:
 * 	Set *after* the victim has been flushed back to memory.
 * 	Set only by victim flush routine.
 * 	Only victims with Flushed set can be viewed as an eviction candidate.
 *
 *    Evicting:
 *      Set when a line is selected to be evicted.
 *      Protected by victim->spinlock.
 *      Used to sync with pcache fill path.
 *
 * C)
 * Victim life time and safety:
 * -------------------------------------------------------------------------
 * |   Victim States                      |            Safety Operations   |
 * -------------------------------------------------------------------------
 * |    Allocated                         |                                |
 * |     ..                               |                                |
 * |    Allocated && *Hasdata*            |-->         ---------------     |
 * |                                      |            pcache hit safe     |
 * |                                      |                                |
 * |                                      |                                |
 * |    Allocated && Hasdata && Writeback |                                |
 * |    ..                                |                                |
 * |    Allocated && Hasdata && *Flushed* |-->         ---------------     |
 * |    ..                                |            pcache hit safe     |
 * |    ..                                |            victim eviction safe|
 * -------------------------------------------------------------------------
 *
 * Pcache hit safe means a victim can be used to fill pcache line.
 *  - Marked by Hasdata
 * Victim eviction safe means a victim can be evicted.
 *  - Marked by Flushed
 *
 * If a victim is both pcache hit safe and victim eviction safe, we need to
 * make sure eviction and fill do not happen at the same time.
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

#define __def_victimflag_names						\
	{1UL << PCACHE_VICTIM_locked,		"locked"	},	\
	{1UL << PCACHE_VICTIM_allocated,	"allocated"	},	\
	{1UL << PCACHE_VICTIM_hasdata,		"hasdata"	},	\
	{1UL << PCACHE_VICTIM_writeback,	"writeback"	},	\
	{1UL << PCACHE_VICTIM_flushed,		"flushed"	},	\
	{1UL << PCACHE_VICTIM_evicting,		"evicting"	},

const struct trace_print_flags victimflag_names[] = {
	__def_victimflag_names
	{0, NULL}
};

void dump_pcache_victim(struct pcache_victim_meta *victim, const char *reason)
{
	pr_debug("victim:%p nr_fill:%d flags:(%pGV)\n",
		victim, atomic_read(&victim->nr_fill_pcache), &victim->flags);
	if (reason)
		pr_debug("victim dumped because: %s\n", reason);
}

static void victim_free_hit_entries(struct pcache_victim_meta *victim);

static void victim_free(struct pcache_victim_meta *v)
{
	/* Only eviction can free */
	PCACHE_BUG_ON_VICTIM(!VictimEvicting(v), v);
	PCACHE_BUG_ON_VICTIM(!VictimAllocated(v) || !VictimFlushed(v) ||
			      VictimWriteback(v) || VictimLocked(v), v);

	victim_free_hit_entries(v);

	/* Clear all flags */
	v->flags = 0;
	smp_wmb();
}

static inline int do_victim_eviction(struct pcache_victim_meta *victim)
{
	victim_free(victim);
	return 0;
}

/*
 * We can ONLY evict line if it has been written back to memory (Flushed).
 * We can NOT evict lines that are currently filling pcache.
 * That is all.
 */
static struct pcache_victim_meta *find_victim_to_evict(void)
{
	int index;
	bool found = false;
	struct pcache_victim_meta *victim;

	for_each_victim(victim, index) {
		/*
		 * Someone freed in the middle
		 * Let caller retry
		 */
		if (!VictimAllocated(victim))
			return NULL;

		/*
		 * Skip lines have not been flushed
		 * Normally they will be flushed back soon
		 */
		if (!VictimFlushed(victim))
			continue;

		spin_lock(&victim->lock);
		if (unlikely(victim_is_filling(victim)))
			PCACHE_BUG_ON_VICTIM(VictimEvicting(victim), victim);
		else {
			SetVictimEvicting(victim);
			found = true;
			spin_unlock(&victim->lock);
			break;
		}
		spin_unlock(&victim->lock);
	}

	if (!found)
		victim = NULL;
	return victim;
}

/*
 * Return 0 if a victim is selected and evicted.
 * Return -EAGAIN if caller should retry this routine.
 * Otherwise on failures.
 */
static int victim_evict_line(void)
{
	struct pcache_victim_meta *victim;

	/* Caller should retry */
	victim = find_victim_to_evict();
	if (!victim)
		return -EAGAIN;

	return do_victim_eviction(victim);
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

/**
 * sysctl_victim_alloc_timeout_sec
 *
 * The maximum time a victim_alloc can take due to slowpath eviction.
 */
unsigned long sysctl_victim_alloc_timeout_sec __read_mostly = 10;

static struct pcache_victim_meta *
victim_alloc_slowpath(void)
{
	struct pcache_victim_meta *victim;
	int ret;
	unsigned long alloc_start = jiffies;

retry:
	ret = victim_evict_line();
	if (ret && ret != -EAGAIN)
		return NULL;

	if (time_after(jiffies,
		       alloc_start + sysctl_victim_alloc_timeout_sec * HZ)) {
		WARN(1, "Abort victim alloc (%ums) pid:%u",
			jiffies_to_msecs(jiffies - alloc_start), current->pid);
		return NULL;
	}

	victim = victim_alloc_fastpath();
	if (!victim)
		goto retry;
	return victim;
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
	atomic_set(&v->nr_fill_pcache, 0);
	v->pcm = NULL;
	return v;
}

/* We might consider kmemcache here */
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

static inline void free_victim_hit_entry(struct pcache_victim_hit_entry *entry)
{
	kfree(entry);
}

static void victim_free_hit_entries(struct pcache_victim_meta *victim)
{
	struct pcache_victim_hit_entry *entry;

	spin_lock(&victim->lock);
	while (!list_empty(&victim->hits)) {
		entry = list_entry(victim->hits.next,
				   struct pcache_victim_hit_entry, next);
		list_del(&entry->next);
		free_victim_hit_entry(entry);
	}
	spin_unlock(&victim->lock);
}

enum victim_check_status {
	VICTIM_CHECK_HIT,
	VICTIM_CHECK_MISS,
	VICTIM_CHECK_EVICTED
};

/*
 * Check if @victim belongs to @address+@tsk
 * Return TRUE if hit, FALSE on miss.
 */
static enum victim_check_status
victim_check_hit_entry(struct pcache_victim_meta *victim,
		       unsigned long address, struct task_struct *tsk)
{
	struct pcache_victim_hit_entry *entry;
	enum victim_check_status result;

	result = VICTIM_CHECK_MISS;
	address &= PAGE_MASK;

	spin_lock(&victim->lock);
	list_for_each_entry(entry, &victim->hits, next) {
		if (entry->address == address &&
		    same_thread_group(entry->owner, tsk)) {

			/*
			 * This line was elected to be evicted, which implies
			 * it must have been flushed back already. We don't race
			 * with eviction, safely return and tell caller to fetch
			 * from remote memory directly.
			 */
			if (unlikely(VictimEvicting(victim))) {
				PCACHE_BUG_ON_VICTIM(!VictimFlushed(victim) ||
						      victim_is_filling(victim),
						      victim);
				result = VICTIM_CHECK_EVICTED;
				goto unlock;
			}

			/*
			 * Mark it so eviction routine will
			 * skip this victim.
			 */
			inc_victim_filling(victim);
			result = VICTIM_CHECK_HIT;
			break;
		}
	}

unlock:
	spin_unlock(&victim->lock);
	return result;
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

/*
 * First step of victim insertion.
 *
 * @pcm was selected to be evicted from pcache, it must already be locked by
 * caller. This function will walk through @pcm rmap list, and add those info
 * into victim cache meta. Afterwards, this victim cache is visible to lookup,
 * but those who do lookup have to wait until the second step of insertion,
 * which is synchronized by Hasdata flag.
 */
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

/*
 * Second step of victim insertion
 *
 * This function is called after fisrt step of insertion and unmap.
 * The sole purpose of func is to copy data from pcache and mark Hasdata.
 */
void victim_finish_insert(struct pcache_victim_meta *victim)
{
	void *src, *dst;
	struct pcache_meta *pcm = victim->pcm;

	BUG_ON(!pcm);
	BUG_ON(!pcache_mapped(pcm));
	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);
	PCACHE_BUG_ON_VICTIM(!VictimAllocated(victim) ||
			      VictimHasdata(victim) ||
			      VictimWriteback(victim), victim);

	/*
	 * Safely copy the pcache line to victim cache
	 * The pcache line was already unmapped and no changes
	 * would be made during memcpy:
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

/* Wait for second step of insertion */
static inline void wait_victim_has_data(struct pcache_victim_meta *victim)
{
	unsigned long wait_start = jiffies;

	while (unlikely(!VictimHasdata(victim))) {
		cpu_relax();
		if (unlikely(time_after(jiffies, wait_start + 5 * HZ)))
			panic("where is the victim finish insertion?");
	}
}

/*
 * Callback for common fill code
 * Fill the pcache line from victim cache
 */
static int
__victim_fill_pcache(unsigned long address, unsigned long flags,
		     struct pcache_meta *pcm, void *_victim)
{
	struct pcache_victim_meta *victim = _victim;
	struct pcache_set *pset;
	void *victim_cache, *pcache;

	victim_cache = pcache_victim_to_kva(victim);
	pcache = pcache_meta_to_kva(pcm);

	wait_victim_has_data(victim);
	smp_rmb();
	memcpy(pcache, victim_cache, PCACHE_LINE_SIZE);

	/* Update counting */
	pset = pcache_meta_to_pcache_set(pcm);
	inc_pset_event(pset, PSET_FILL_VICTIM);
	inc_pcache_event(PCACHE_FAULT_FILL_VICTIM);

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

/* Return 0 on success, otherwise on failures */
int victim_try_fill_pcache(struct mm_struct *mm, unsigned long address,
			   pte_t *page_table, pmd_t *pmd,
			   unsigned long flags)
{
	struct pcache_victim_meta *victim;
	int index, ret = 1;

	for_each_victim(victim, index) {
		/*
		 * The following case may happen:
		 * Even victim_may_hit() returns true, but another CPU
		 * may evict the corresponding victim cache line right before
		 * we do the following Allocated checking. This means we will
		 * miss the victim hit chance. But logically this is correct.
		 */
		if (!VictimAllocated(victim))
			continue;

		switch (victim_check_hit_entry(victim, address, current)) {
		case VICTIM_CHECK_MISS:
			continue;
		case VICTIM_CHECK_EVICTED:
			/*
			 * It is actually a hit, but unfortunately it is
			 * being evicted at the same time. Return early.
			 */
			return 1;
		case VICTIM_CHECK_HIT:
			ret = victim_fill_pcache(mm, address, page_table,
						 pmd, flags, victim);
			/*
			 * Filling to pcache is done, so this victim
			 * is again safe to be evicted.
			 */
			dec_victim_filling(victim);
			break;
		default:
			BUG();
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
		atomic_set(&v->nr_fill_pcache, 0);
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
