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
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/jiffies.h>
#include <lego/kthread.h>
#include <lego/profile.h>
#include <lego/memblock.h>
#include <lego/completion.h>
#include <processor/node.h>
#include <processor/distvm.h>
#include <processor/pcache.h>
#include <processor/processor.h>

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
 *
 * B)
 * victim->flags
 *
 *    Allocated:
 * 	Set when victim is used, clear when free.
 * 	Simply used to guide victim allocation/free.
 *
 *    Usable:
 *      Set when the victim is all initialized.
 *      Others only use Usable victim
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
 *    Reclaim:
 *      Set when a line is selected to be evicted.
 *      Protected by victim->spinlock.
 *      Used to sync with pcache fill path.
 *
 * C)
 * Victim life time and safety:
 * -----------------------------------------------------------------------------------
 * |   Victim States                                |            Safety Operations   |
 * ----------------------------------------------------------------------------------|
 * |    Allocated                                   |                                |
 * |    ..                                          |                                |
 * |    Allocated && Usable                         |                                |
 * |     ..                                         |                                |
 * |    Allocated && Usable && *Hasdata*            |-->         ---------------     |
 * |                                                |            pcache hit safe     |
 * |                                                |                                |
 * |                                                |                                |
 * |    Allocated && Usable && Hasdata && Writeback |                                |
 * |    ..                                          |                                |
 * |    Allocated && Usable && Hasdata && *Flushed* |-->         ---------------     |
 * |    ..                                          |            pcache hit safe     |
 * |    ..                                          |            victim eviction safe|
 * -----------------------------------------------------------------------------------
 *
 * Pcache hit safe means a victim can be used to fill pcache line.
 *  - Marked by Hasdata
 * Victim eviction safe means a victim can be evicted.
 *  - Marked by Flushed
 *
 * D)
 * If a victim is both pcache hit safe and victim eviction safe, we need to
 * make sure eviction and fill do not happen at the same time. What we are
 * doing here is to use Reclaim flag and a filling counter. Both parties
 * need to first acquire victim->lock and do checking/updating. This ensures
 * up filling to pcache and victim evictim won't conflict.
 * (victim_check_hit_entry() and find_victim_to_evict())
 *
 * E)
 * Lock ordering:
 *  usable_victims_lock
 *   .. victim->lock
 */

#ifdef CONFIG_DEBUG_PCACHE_VICTIM
#define victim_debug(fmt, ...)				\
	pr_debug("%s() CPU:%d PID:%d " fmt "\n",	\
		__func__, smp_processor_id(), current->pid, __VA_ARGS__)
#else
static inline void victim_debug(const char *fmt, ...) { }
#endif

struct pcache_victim_meta *pcache_victim_meta_map __read_mostly;
void *pcache_victim_data_map __read_mostly;

static atomic_t nr_usable_victims = ATOMIC_INIT(0);
static LIST_HEAD(usable_victims);
static DEFINE_SPINLOCK(usable_victims_lock);

/* FIFO: Add to tail, while eviction search from head */
static inline void __enqueue_usable_victim(struct pcache_victim_meta *v)
{
	list_add_tail(&v->next, &usable_victims);
	atomic_inc(&nr_usable_victims);
}

static inline void enqueue_usable_victim(struct pcache_victim_meta *v)
{
	spin_lock(&usable_victims_lock);
	__enqueue_usable_victim(v);
	spin_unlock(&usable_victims_lock);
}

static inline void __dequeue_usable_victim(struct pcache_victim_meta *v)
{
	list_del_init(&v->next);
	atomic_dec(&nr_usable_victims);
}

static inline void dequeue_usable_victim(struct pcache_victim_meta *v)
{
	spin_lock(&usable_victims_lock);
	__dequeue_usable_victim(v);
	spin_unlock(&usable_victims_lock);
}

static void victim_free_hit_entries(struct pcache_victim_meta *victim);

static void inline __put_victim_nolist(struct pcache_victim_meta *v)
{
	PCACHE_BUG_ON_VICTIM(victim_ref_count(v), v);
	PCACHE_BUG_ON_VICTIM(!VictimAllocated(v) || !VictimUsable(v) ||
			     !VictimFlushed(v) || VictimWriteback(v) ||
			     VictimLocked(v), v);

	victim_free_hit_entries(v);

	/* Clear all flags */
	smp_store_mb(v->flags, 0);
}

/* Called when refcount drops to 0 */
void __put_victim(struct pcache_victim_meta *v)
{
	dequeue_usable_victim(v);
	__put_victim_nolist(v);
}

/*
 * We can ONLY evict line if it has been written back to memory (Flushed).
 * We can NOT evict lines that are currently filling back to pcache.
 * And we only check usable lines.
 *
 * Search based on FIFO order.
 */
static struct pcache_victim_meta *
find_victim_to_evict(void)
{
	bool found = false;
	struct pcache_victim_meta *v, *saver;

	if (atomic_read(&nr_usable_victims) < VICTIM_NR_ENTRIES)
		return NULL;

	victim_debug("begin selection. nr_allocated: %d",
		atomic_read(&nr_usable_victims));

	spin_lock(&usable_victims_lock);
	list_for_each_entry_safe(v, saver, &usable_victims, next) {
		PCACHE_BUG_ON_VICTIM(!VictimUsable(v), v);
		PCACHE_BUG_ON_VICTIM(VictimReclaim(v), v);

		victim_debug("  victim:%p index:%d refcount:%d nr_fill:%d locked:%d flags:(%pGV) "
			 "pcm:%p pset:%p\n",
			v, victim_index(v), atomic_read(&v->_refcount),
			atomic_read(&v->nr_fill_pcache), spin_is_locked(&v->lock),
			&v->flags, v->pcm, v->pset);

		/*
		 * Grab a ref first in case it goes away,
		 * Check if someone else freed one before us.
		 */
		if (unlikely(!get_victim_unless_zero(v)))
			goto out_unlock_list;

		/*
		 * Skip victim that has not been flushed back,
		 * kvictim_flushd will flush it soon.
		 * Flushed also implies it must have data
		 */
		if (!VictimFlushed(v))
			goto loop_put;
		PCACHE_BUG_ON_VICTIM(!VictimHasdata(v), v);

		/* Lock contention? */
		if (!spin_trylock(&v->lock))
			goto loop_put;

		/*
		 * Skip victim that is filling back to pcache
		 * Synchronize with victim_try_fill_pcache()
		 */
		if (unlikely(victim_is_filling(v)))
			goto loop_unlock_victim;
		if (unlikely(VictimFillfree(v)))
			goto loop_unlock_victim;

		/*
		 * 1 for original allocation
		 * 1 for get_victim above
		 * Otherwise it is used by others
		 *
		 * XXX
		 * Currently only eviction, filling, flush routines
		 * those are syned by different things. And this simple
		 * refcount check should work. Be careful if we add more.
		 */
		if (unlikely(victim_ref_count(v) > 2))
			goto loop_unlock_victim;

		/*
		 * Yeah! We have a victim candidate that is:
		 * 1) Flushed
		 * 2) locked by us
		 * 3) not filling pcache
		 *
		 * Now set the Reclaim flag, unlock the victim,
		 * and remove it from usable_victims_list.
		 * But we still hold 1 more ref here.
		 */
		if (unlikely(TestSetVictimReclaim(v))) {
			dump_pcache_victim(v, NULL);
			BUG();
		}
		spin_unlock(&v->lock);
		__dequeue_usable_victim(v);

		found = true;
		goto out_unlock_list;

loop_unlock_victim:
		spin_unlock(&v->lock);
loop_put:
		/*
		 * Someone else may have freed a victim, if that is case,
		 * jump out and let caller retry:
		 */
		if (unlikely(put_victim_testzero(v))) {
			__dequeue_usable_victim(v);
			__put_victim_nolist(v);
			goto out_unlock_list;
		}
	}

out_unlock_list:
	spin_unlock(&usable_victims_lock);

	if (likely(found)) {
		victim_debug("finish selection, evict v%u", victim_index(v));
		return v;
	}
	return NULL;
}

/*
 * Return 0 if a victim is selected and evicted.
 * Return -EAGAIN if caller should retry this routine.
 * Otherwise on failures.
 */
static int victim_evict_line(void)
{
	struct pcache_victim_meta *victim;

	inc_pcache_event(PCACHE_VICTIM_EVICTION_TRIGGERED);

	/*
	 * If a victim is selected to be evicted, it is removed
	 * from the allocated_victim list, and has Reclaim flag set.
	 * Also it has ref=1 or ref=2.
	 */
	victim = find_victim_to_evict();
	if (!victim) {
		inc_pcache_event(PCACHE_VICTIM_EVICTION_EAGAIN);
		return -EAGAIN;
	}
	PCACHE_BUG_ON_VICTIM(!VictimReclaim(victim), victim);

	if (victim_ref_freeze(victim, 2))
		__put_victim_nolist(victim);
	else {
		dump_pcache_victim(victim, NULL);
		WARN_ON_ONCE(1);
	}

	inc_pcache_event(PCACHE_VICTIM_EVICTION_SUCCEED);
	return 0;
}

static inline void prep_new_victim(struct pcache_victim_meta *victim)
{
	/*
	 * ref count = 1 for the caller
	 */
	victim_ref_count_set(victim, 1);

	victim->pcm = NULL;
	victim->pset = NULL;
	atomic_set(&victim->nr_fill_pcache, 0);
	INIT_LIST_HEAD(&victim->next);
}

static struct pcache_victim_meta *
victim_alloc_fastpath(void)
{
	int index;
	struct pcache_victim_meta *v;

	spin_lock(&usable_victims_lock);
	for_each_victim(v, index) {
		if (likely(!TestSetVictimAllocated(v))) {
			prep_new_victim(v);
			__enqueue_usable_victim(v);

			/*
			 * Make the victim line visible to other
			 * victim code such as pgfault fill path:
			 */
			set_victim_usable(v);
			spin_unlock(&usable_victims_lock);
			return v;
		}
	}
	spin_unlock(&usable_victims_lock);

	return NULL;
}

/**
 * sysctl_victim_alloc_timeout_sec
 *
 * The maximum time a victim_alloc can take due to slowpath eviction.
 */
unsigned long sysctl_victim_alloc_timeout_sec __read_mostly = 20;

DEFINE_PROFILE_POINT(victim_alloc_slowpath)

static struct pcache_victim_meta *
victim_alloc_slowpath(struct pcache_set *pset)
{
	struct pcache_victim_meta *victim;
	int ret;
	unsigned long alloc_start = jiffies;
	PROFILE_POINT_TIME(victim_alloc_slowpath)

	PROFILE_START(victim_alloc_slowpath);
retry:
	ret = victim_evict_line();
	if (ret && ret != -EAGAIN) {
		PROFILE_LEAVE(victim_alloc_slowpath);
		return NULL;
	}

	if (time_after(jiffies, alloc_start + sysctl_victim_alloc_timeout_sec * HZ)) {
		/*
		 * If this got printed, nr_lru will not equal to PCACHE_ASSOCIATIVTY.
		 * In fact, it must equal to (PCACHE_ASSOCIATIVITY - 1).
		 * Because one @pcm has been removed from list as the eviction candidate.
		 */
		pr_info("CPU%d PID:%d Abort victim alloc (%ums) nr_usable_victims: %d "
		        "req from pset:%p, pset_idx:%lu, nr_lru:%d\n",
			smp_processor_id(), current->pid,
			jiffies_to_msecs(jiffies - alloc_start),
			atomic_read(&nr_usable_victims),
			pset, pcache_set_to_set_index(pset),
			IS_ENABLED(CONFIG_PCACHE_EVICT_LRU) ? atomic_read(&pset->nr_lru) : 0);
		dump_victim_lines_and_queue();
		PROFILE_LEAVE(victim_alloc_slowpath);
		return NULL;
	}

	victim = victim_alloc_fastpath();
	if (!victim)
		goto retry;

	PROFILE_LEAVE(victim_alloc_slowpath);
	return victim;
}

static struct pcache_victim_meta *victim_alloc(struct pcache_set *pset)
{
	struct pcache_victim_meta *v;

	v = victim_alloc_fastpath();
	if (likely(v))
		return v;

	v = victim_alloc_slowpath(pset);
	if (likely(v))
		return v;
	return NULL;
}

/* We might consider kmemcache here */
static inline struct pcache_victim_hit_entry *
alloc_victim_hit_entry(void)
{
	struct pcache_victim_hit_entry *entry;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
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
	struct pcache_set *pset = victim->pset;

	/*
	 * Update hint counting
	 * to avoid un-necessary lookup
	 */
	pcache_set_victim_dec(pset);

	spin_lock(&victim->lock);
	while (!list_empty(&victim->hits)) {
		entry = list_entry(victim->hits.next,
				   struct pcache_victim_hit_entry, next);
		list_del(&entry->next);
		free_victim_hit_entry(entry);
	}
	spin_unlock(&victim->lock);
}

static int victim_insert_hit_entry(struct pcache_meta *pcm,
				   struct pcache_rmap *rmap, void *arg)
{
	struct pcache_victim_meta *victim = arg;
	struct pcache_victim_hit_entry *hit;

	victim_debug("pcm: %p, uva: %#lx, owner_tgid: %d",
		pcm, rmap->address, rmap->owner_process->tgid);

	hit = alloc_victim_hit_entry();
	if (!hit)
		return PCACHE_RMAP_FAILED;

	hit->address = rmap->address;
	hit->tgid = rmap->owner_process->tgid;

	/*
	 * This rmap belongs the current evicted pcm
	 * This pcm has been locked, which implies rmap->owner_process
	 * stay valid even if it is under exit_mm stuff.
	 *
	 * XXX
	 * This is not true. Check log 0419-w15-4. If owner_process, which
	 * is the thread group leader has been zapped by another thread,
	 * then ->mm will be NULL.
	 */
	hit->m_nid = get_memory_node(rmap->owner_process, rmap->address);
	hit->rep_nid = get_replica_node_by_addr(rmap->owner_process, rmap->address);

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

DEFINE_PROFILE_POINT(victim_alloc)

/*
 * First step of victim insertion.
 *
 * @pcm was selected to be evicted from pcache, it must already be locked by
 * caller. This function will walk through @pcm rmap list, and add those info
 * into victim cache meta. Afterwards, this victim cache is visible to lookup,
 * but those who do lookup have to wait until the second step of insertion,
 * which is synchronized by Hasdata flag.
 *
 * Another note: since we will free the victim cache line once it filled
 * back to pcache, therefore, there is no need to check duplication here.
 */
struct pcache_victim_meta *
victim_prepare_insert(struct pcache_set *pset, struct pcache_meta *pcm)
{
	int ret;
	struct pcache_victim_meta *victim;
	PROFILE_POINT_TIME(victim_alloc)

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);

	/*
	 * Update counter even before we allocate
	 * Because we want to catch the failed allocation
	 */
	inc_pcache_event(PCACHE_VICTIM_PREPARE_INSERT);

	PROFILE_START(victim_alloc);
	victim = victim_alloc(pset);
	PROFILE_LEAVE(victim_alloc);
	if (!victim)
		return ERR_PTR(-ENOMEM);
	victim->pset = pset;

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

DEFINE_PROFILE_POINT(victim_submit_flush)

/*
 * Second step of victim insertion
 *
 * This function is called after fisrt step of insertion and unmap.
 * The purpose of func are:
 *  - copy data from pcache and mark Hasdata.
 *  - submit flush job if the pcache line was dirty
 */
void victim_finish_insert(struct pcache_victim_meta *victim, bool dirty)
{
	void *src, *dst;
	struct pcache_meta *pcm = victim->pcm;
	PROFILE_POINT_TIME(victim_submit_flush)

	victim_debug("pcm: %p v%u", pcm, victim_index(victim));

	BUG_ON(!pcm);
	PCACHE_BUG_ON_PCM(pcache_mapped(pcm), pcm);
	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);
	PCACHE_BUG_ON_VICTIM(!VictimAllocated(victim) ||
			      VictimHasdata(victim) ||
			      VictimWriteback(victim), victim);

	/*
	 * We grab 1 ref for victim flush, in case the
	 * victim went away. We do this ahead in case
	 * it went away by a victim hit, even before we
	 * reach the submit work part.
	 */
	if (unlikely(!get_victim_unless_zero(victim))) {
		dump_pcache_victim(victim, "error free");
		WARN_ON_ONCE(1);
		return;
	}

	/*
	 * Safely (i.e. atomic) copy the pcache line to victim cache
	 * The pcache line was already unmapped and no changes
	 * would be made during memcpy:
	 */
	src = pcache_meta_to_kva(pcm);
	dst = pcache_victim_to_kva(victim);
	memcpy(dst, src, PCACHE_LINE_SIZE);

	victim->pcm = NULL;
	smp_wmb();
	SetVictimHasdata(victim);

	/* Update counter */
	inc_pcache_event(PCACHE_VICTIM_FINISH_INSERT);

	/*
	 * Submit flush job to daemon flush thread
	 * Don't wait for the slow flush.
	 * We are in pgfault critical path.
	 */
	PROFILE_START(victim_submit_flush);
	victim_submit_flush_nowait(victim, dirty);
	PROFILE_LEAVE(victim_submit_flush);
}

/* Wait for second step of insertion */
static inline void wait_victim_has_data(struct pcache_victim_meta *victim)
{
	unsigned long wait_start = jiffies;

	while (unlikely(!VictimHasdata(victim))) {
		cpu_relax();

		/* Break out after 10 seconds */
		if (unlikely(time_after(jiffies, wait_start + 10 * HZ)))
			panic("where is the victim finish insertion?");
	}
}

DEFINE_PROFILE_POINT(__pcache_fill_victim)

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
	PROFILE_POINT_TIME(__pcache_fill_victim)

	PROFILE_START(__pcache_fill_victim);

	victim_cache = pcache_victim_to_kva(victim);
	pcache = pcache_meta_to_kva(pcm);

	wait_victim_has_data(victim);
	smp_rmb();
	memcpy(pcache, victim_cache, PCACHE_LINE_SIZE);

	/* Update counting */
	pset = pcache_meta_to_pcache_set(pcm);
	inc_pset_event(pset, PSET_FILL_VICTIM);
	inc_pcache_event(PCACHE_FAULT_FILL_FROM_VICTIM);

	PROFILE_LEAVE(__pcache_fill_victim);
	return 0;
}

/*
 * This function will fill the pcache line from victim cache.
 * If this fails, caller needs to fallback to remote memory.
 *
 * HACK!!! Please note the @orig_pte passed by handle_pte_fault() is crutial
 * for SMP case. It is the @orig_pte that initially lead the code path here.
 * If we do a *page_table instead of @orig_pte, that will break all the conditions
 * that lead us here to be false, and it is very easy to falsely get pte_same()
 * holds true in common_do_fill_page().
 *
 * Return 0 on success, otherwise on VM_FAULT_XXX flags
 */
static inline int
victim_fill_pcache(struct mm_struct *mm, unsigned long address,
		   pte_t *page_table, pte_t orig_pte, pmd_t *pmd, unsigned long flags,
		   struct pcache_victim_meta *victim)
{
	return common_do_fill_page(mm, address, page_table, orig_pte, pmd, flags,
			__victim_fill_pcache, victim, RMAP_VICTIM_FILL);
}

enum victim_check_status {
	VICTIM_MISS,
	VICTIM_HIT,
	VICTIM_HIT_FREED,
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

	result = VICTIM_MISS;
	address &= PAGE_MASK;

	spin_lock(&victim->lock);
	list_for_each_entry(entry, &victim->hits, next) {
		victim_debug("    v%d[%#lx %d] u[%#lx %d]",
			victim_index(victim), entry->address, entry->tgid,
			address, tsk->tgid);

		if (entry->address == address &&
		    entry->tgid == tsk->tgid) {
			/*
			 * Increment the fill counter
			 * We are no longer an eviction candidate
			 */
			__SetVictimFillfree(victim);
			inc_victim_filling(victim);
			result = VICTIM_HIT;
			break;
		}
	}
	spin_unlock(&victim->lock);
	return result;
}

/*
 * Try to find if victim contains cache line maps to @address and current.
 * We walk through all allocated victim cache lines and check one by one.
 *
 * Return 0 on success, otherwise on failures
 */
int victim_try_fill_pcache(struct mm_struct *mm, unsigned long address,
			   pte_t *page_table, pte_t orig_pte, pmd_t *pmd,
			   unsigned long flags)
{
	struct pcache_victim_meta *v;
	enum victim_check_status result;
	int ret = 1;

	victim_debug("checking uva: %#lx tgid: %d", address, current->tgid);

        inc_pcache_event(PCACHE_VICTIM_LOOKUP);

	spin_lock(&usable_victims_lock);
	list_for_each_entry(v, &usable_victims, next) {
		PCACHE_BUG_ON_VICTIM(!VictimUsable(v), v);
		PCACHE_BUG_ON_VICTIM(VictimReclaim(v), v);

		if (unlikely(!get_victim_unless_zero(v)))
			continue;

		result = victim_check_hit_entry(v, address, current);
		if (result == VICTIM_HIT) {
			/*
			 * victim_fill_pcache will call back to pcache fill code,
			 * which will further try to allocate a pcache line.
			 * If pcache is already full, it will evict one to victim.
			 * If victim is also full, victim needs to evict one, too.
			 * This eventually goes to find_victim_to_evict().
			 * So, _don't_ hold the same lock:
			 */
			spin_unlock(&usable_victims_lock);
                        inc_pcache_event(PCACHE_VICTIM_HIT);

			ret = victim_fill_pcache(mm, address, page_table, orig_pte,
						 pmd, flags, v);

			/* Paired with above get */
			if (put_victim_testzero(v)) {
				dequeue_usable_victim(v);
				__put_victim_nolist(v);
				return ret;
			}

			if (likely(dec_and_test_victim_filling(v))) {
				if (!ret)
					put_victim(v);
			}
			goto out;
		} else if (result == VICTIM_MISS) {
			/*
			 * If it is miss, we do not need to release the lock.
			 * But we do need to decrement 1 reference. Meanwhile
			 * there might be another thread having a hit and tried
			 * to free the pcache line:
			 */
			if (unlikely(put_victim_testzero(v))) {
				__dequeue_usable_victim(v);
				__put_victim_nolist(v);
			}
			continue;
		} else
			BUG();
	}
	spin_unlock(&usable_victims_lock);
out:
	return ret;
}

static void __init victim_cache_init_meta_map(void)
{
	int i;

	/* Initialize each victim meta */
	for (i = 0; i < VICTIM_NR_ENTRIES; i++) {
		struct pcache_victim_meta *v;

		v = pcache_victim_meta_map + i;

		v->flags = 0;
		v->pcm = NULL;
		v->pset = NULL;
		spin_lock_init(&v->lock);
		INIT_LIST_HEAD(&v->hits);
		INIT_LIST_HEAD(&v->next);
		atomic_set(&v->nr_fill_pcache, 0);
		atomic_set(&v->max_nr_fill_pcache, 0);
		victim_ref_count_set(v, 0);
	}
}

/*
 * Allocate victim metadata and cache lines
 * This function is called during early boot, both buddy allocator
 * and slab are not avaiable. Use memblock instead.
 */
void __init victim_cache_early_init(void)
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

	victim_cache_init_meta_map();
}
