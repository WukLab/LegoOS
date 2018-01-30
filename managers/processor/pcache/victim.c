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
 * D)
 * If a victim is both pcache hit safe and victim eviction safe, we need to
 * make sure eviction and fill do not happen at the same time. What we are
 * doing here is to use Evicting flag and a filling counter. Both parties
 * need to first acquire victim->lock and do checking/updating. This ensures
 * up filling to pcache and victim evictim won't conflict.
 * (victim_check_hit_entry() and find_victim_to_evict())
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

/*
 * Lock ordering:
 *  allocated_victims_lock
 *   .. victim->lock
 *
 * Note for myself:
 * This list is for lookup and eviction search. Why do we need such a list
 * instead of just searching victim array map? At first glance, Allocated
 * bit seems enough: lookup and eviction can just check the bit and skip
 * the one has not been allocated. This is okay if only eviction can free
 * a victim. But now lookup also need to free. So there is an issue: image
 * there are 2 CPUs, one is doing eviction, one is doing lookup. The lookup
 * one freed the victim right after eviction checking the Allocated bit.
 * This means eviction is now manipulating a freed victim, which is wrong.
 *
 * The whole issue is raised because eviction and lookup they are looking into
 * data structures that they should not have permission to look into. They
 * should only look into victims that have been allocated, instead of walking
 * through the whole victim array map.
 *
 * This issue is very very similar to LRU page reclaim. Without LRU, there
 * is only one party can free page. With LRU, there are now two parties
 * can free page. One party can not free page while another one is using it.
 * Also more importanly, LRU only have permissions to look into pages that
 * are explicitly added to lru lists. That is the key similarity here.
 *
 * Of course, the above issue concerned multiple parties can be easily solved
 * by adding a reference count, and each party do paired get/put_xxx functions.
 * We also have this, because lookup may free the victim while the flush thread
 * is using it.
 *
 * This whole victim cache development is a valuable lesson for my self.
 * Whenever developing this kind of subsystem, keep few things in mind:
 * 1) Think broader. Don't assume too much things in the beginning (e.g. only
 *    eviction will do free).
 * 2) Reference counter. If a data structure is used by multiple parties,
 *    rememeber to protect it using get/put functions. Always.
 * 3) Permission. Don't give functions permissions to data structures that
 *    they should not have permissions to manipulate. This will break other
 *    parties who are using this data structure.
 */
static atomic_t nr_allocated_victims = ATOMIC_INIT(0);
static LIST_HEAD(allocated_victims);
static DEFINE_SPINLOCK(allocated_victims_lock);

static inline void __enqueue_allocated_victim(struct pcache_victim_meta *v)
{
	list_add_tail(&v->next, &allocated_victims);
	atomic_inc(&nr_allocated_victims);
}

static inline void enqueue_allocated_victim(struct pcache_victim_meta *v)
{
	spin_lock(&allocated_victims_lock);
	__enqueue_allocated_victim(v);
	spin_unlock(&allocated_victims_lock);
}

static inline void __dequeue_allocated_victim(struct pcache_victim_meta *v)
{
	list_del_init(&v->next);
	atomic_dec(&nr_allocated_victims);
}

static inline void dequeue_allocated_victim(struct pcache_victim_meta *v)
{
	spin_lock(&allocated_victims_lock);
	__dequeue_allocated_victim(v);
	spin_unlock(&allocated_victims_lock);
}

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
	pr_debug("victim:%p refcount:%d nr_fill:%d locked:%d flags:(%pGV)\n",
		victim, atomic_read(&victim->_refcount),
		atomic_read(&victim->nr_fill_pcache), spin_is_locked(&victim->lock),
		&victim->flags);
	if (reason)
		pr_debug("victim dumped because: %s\n", reason);
}

static void victim_free_hit_entries(struct pcache_victim_meta *victim);

static void __put_victim_nolist(struct pcache_victim_meta *v)
{
	PCACHE_BUG_ON_VICTIM(victim_ref_count(v), v);

	PCACHE_BUG_ON_VICTIM(!VictimAllocated(v) || !VictimFlushed(v) ||
			      VictimWriteback(v) || VictimLocked(v), v);

	victim_free_hit_entries(v);

	/* Clear all flags */
	smp_wmb();
	v->flags = 0;
}

/* Called when refcount drops to 0 */
void __put_victim(struct pcache_victim_meta *v)
{
	dequeue_allocated_victim(v);
	__put_victim_nolist(v);
}

/*
 * We can ONLY evict line if it has been written back to memory (Flushed).
 * We can NOT evict lines that are currently filling back to pcache.
 * That is all.
 */
static struct pcache_victim_meta *
find_victim_to_evict(void)
{
	bool found = false;
	struct pcache_victim_meta *v, *saver;

	if (atomic_read(&nr_allocated_victims) < VICTIM_NR_ENTRIES)
		return NULL;

	victim_debug("begin selection. nr_allocated: %d",
		atomic_read(&nr_allocated_victims));

	spin_lock(&allocated_victims_lock);
	list_for_each_entry_safe(v, saver, &allocated_victims, next) {
		PCACHE_BUG_ON_VICTIM(!VictimAllocated(v), v);
		PCACHE_BUG_ON_VICTIM(VictimEvicting(v), v);

		/*
		 * Grab a ref first in case it goes away,
		 * Check if someone else freed one before us.
		 */
		if (unlikely(!get_victim_unless_zero(v)))
			goto out_unlock_list;

		/*
		 * Skip victim that has not been flushed back,
		 * kvictim_flushd will flush it soon.
		 */
		if (!VictimFlushed(v))
			goto loop_put;

		/* Flushed also implies it must have data */
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
		 * Now set the Evicting flag, unlock the victim,
		 * and remove it from allocated_victims_list.
		 * But we still hold 1 more ref here.
		 */
		if (unlikely(TestSetVictimEvicting(v))) {
			dump_pcache_victim(v, NULL);
			BUG();
		}
		spin_unlock(&v->lock);
		__dequeue_allocated_victim(v);

		found = true;
		goto out_unlock_list;

loop_unlock_victim:
		spin_unlock(&v->lock);
loop_put:
		/*
		 * Someone else freed a victim, jump out and retry.
		 * We are still holding the list lock, be careful.
		 */
		if (unlikely(put_victim_testzero(v))) {
			__dequeue_allocated_victim(v);
			__put_victim_nolist(v);
			goto out_unlock_list;
		}
	}

out_unlock_list:
	spin_unlock(&allocated_victims_lock);

	if (likely(found))
		return v;
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

	/*
	 * If a victim is selected to be evicted, it is removed
	 * from the allocated_victim list, and has Evicting flag set.
	 * Also it has ref=1 or ref=2.
	 */
	victim = find_victim_to_evict();
	if (!victim)
		return -EAGAIN;

	PCACHE_BUG_ON_VICTIM(!VictimEvicting(victim), victim);
	if (unlikely(victim_ref_count(victim) > 2)) {
		dump_pcache_victim(victim, "victim/ref bug");
		BUG();
	}

	/*
	 * This victim is out of allocated list now, thus it is impossible
	 * for others to see it. We are currently the *only* user can see,
	 * and use this victim. Therefore, it is safe to manually set its
	 * refcount to 0, and then free.
	 */
	victim_ref_count_set(victim, 0);
	__put_victim_nolist(victim);

	inc_pcache_event(PCACHE_VICTIM_EVICTION);
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

	for_each_victim(v, index) {
		if (likely(!TestSetVictimAllocated(v))) {
			prep_new_victim(v);
			enqueue_allocated_victim(v);
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
		return v;

	v = victim_alloc_slowpath();
	if (likely(v))
		return v;
	return NULL;
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

	victim_debug("pcm: %p, uva: %#lx, owner_pid: %d",
		pcm, rmap->address & PAGE_MASK, rmap->owner->pid);

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
 *
 * Another note: since we will free the victim cache line once it filled
 * back to pcache, therefore, there is no need to check duplication here.
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

	victim_debug("pcm: %p victim: %p", pcm, victim);

	BUG_ON(!pcm);
	PCACHE_BUG_ON_PCM(pcache_mapped(pcm), pcm);
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

	victim->pcm = NULL;
	smp_wmb();
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
	inc_pcache_event(PCACHE_FAULT_FILL_FROM_VICTIM);

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

enum victim_check_status {
	VICTIM_CHECK_MISS,
	VICTIM_CHECK_HIT,
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
			 * Mark it so eviction routine will
			 * skip this victim.
			 */
			inc_victim_filling(victim);
			result = VICTIM_CHECK_HIT;
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
			   pte_t *page_table, pmd_t *pmd,
			   unsigned long flags)
{
	struct pcache_victim_meta *v, *saver;
	enum victim_check_status result;
	int ret = 1;

	victim_debug("for uva: %#lx", address);

	spin_lock(&allocated_victims_lock);
	list_for_each_entry_safe(v, saver, &allocated_victims, next) {
		PCACHE_BUG_ON_VICTIM(!VictimAllocated(v), v);

		/* Evicting victim is removed from list */
		PCACHE_BUG_ON_VICTIM(VictimEvicting(v), v);

		result = victim_check_hit_entry(v, address, current);
		victim_debug("hit: %d address: %#lx victim: %p",
			result, address, v);

		switch (result) {
		case VICTIM_CHECK_HIT:
			ret = victim_fill_pcache(mm, address, page_table,
						 pmd, flags, v);

			/*
			 * Drop the victim once hit by pcache
			 * (flush may hold another ref meanwhile)
			 */
			if (dec_and_test_victim_filling(v) && !ret) {
				if (likely(put_victim_testzero(v))) {
					__dequeue_allocated_victim(v);
					__put_victim_nolist(v);
				}
			}
			goto out;
		case VICTIM_CHECK_MISS:
			break;

			/*
			 * Another case is victim is being evicted. This implies
			 * that victim has *already* be flushed back to memory,
			 * otherwise it will not be selected to be evicted.
			 */
		default:
			BUG();
		}

	}
out:
	spin_unlock(&allocated_victims_lock);
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
