/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Victim cache's background flush daemon thread
 */

#include <lego/mm.h>
#include <lego/smp.h>
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
#include <lego/comp_common.h>
#include <lego/completion.h>
#include <processor/pcache.h>
#include <processor/processor.h>

atomic_t nr_flush_jobs = ATOMIC_INIT(0);
DEFINE_SPINLOCK(victim_flush_lock);
LIST_HEAD(victim_flush_queue);
static struct task_struct *victim_flush_thread;

static inline void __dequeue_victim_flush_job(struct victim_flush_job *job)
{
	list_del(&job->next);
	atomic_dec(&nr_flush_jobs);

	/* Sane test only if DEBUG_PCACHE is on */
	PCACHE_BUG_ON(atomic_read(&nr_flush_jobs) < 0);
}

static inline void __enqueue_victim_flush_job(struct victim_flush_job *job)
{
	list_add_tail(&job->next, &victim_flush_queue);
	atomic_inc(&nr_flush_jobs);

	/* Sane test only if DEBUG_PCACHE is on */
	PCACHE_BUG_ON(atomic_read(&nr_flush_jobs) > VICTIM_NR_ENTRIES);
}

static inline void dequeue_victim_flush_job(struct victim_flush_job *job)
{
	spin_lock(&victim_flush_lock);
	__dequeue_victim_flush_job(job);
	spin_unlock(&victim_flush_lock);
}

static inline void enqueue_victim_flush_job(struct victim_flush_job *job)
{
	spin_lock(&victim_flush_lock);
	__enqueue_victim_flush_job(job);
	spin_unlock(&victim_flush_lock);
}

/*
 * Submit a victim cache line to flush queue.
 * @wait: true if you want to wait for completion
 * @bool: if the pcache line was dirty before unmapped
 */
int victim_submit_flush(struct pcache_victim_meta *victim, bool wait, bool dirty)
{
	struct victim_flush_job *job;

	PCACHE_BUG_ON_VICTIM(!VictimHasdata(victim) || !VictimAllocated(victim), victim);
	PCACHE_BUG_ON_VICTIM(VictimFlushed(victim) || VictimWriteback(victim) ||
			     VictimWaitflush(victim), victim);

	/*
	 * If the pcache line was clean, then there is no need to
	 * flush back to remote memory. But we do need to set
	 * the Flushed flag, to mark this victim as a candidate.
	 * Similar to the cleanup if a dirty line was flushed.
	 */
	if (!dirty) {
		SetVictimFlushed(victim);
		inc_pcache_event(PCACHE_VICTIM_FLUSH_SUBMITTED_CLEAN);
		inc_pcache_event(PCACHE_CLFLUSH_CLEAN_SKIPPED);
		return 0;
	}

	__SetVictimWaitflush(victim);

	get_victim(victim);

	job = kmalloc(sizeof(*job), GFP_KERNEL);
	if (WARN_ON(!job))
		return -ENOMEM;
	job->victim = victim;
	job->wait = wait;
	if (unlikely(wait))
		init_completion(&job->done);

	enqueue_victim_flush_job(job);
	inc_pcache_event(PCACHE_VICTIM_FLUSH_SUBMITTED_DIRTY);

	/* flush thread will free job */
	if (unlikely(wait))
		wait_for_completion(&job->done);
	return 0;
}

/*
 * Return number of succeed clflush
 * It can be 0, if the address belonged area was unmapped
 */
static void victim_flush_one(struct pcache_victim_meta *victim)
{
	void *cache_kva;
	struct pcache_victim_hit_entry *entry;

	cache_kva = pcache_victim_to_kva(victim);

	/*
	 * We don't need acquire the spinlock to walk through
	 * the list at this point: 1) Eviction won't take this
	 * victim cause Flushed is not set. 2) Insertion only
	 * happens once and it already happened.
	 */
	list_for_each_entry(entry, &victim->hits, next)
		__clflush_one(entry->tgid, entry->address,
			      entry->m_nid, entry->rep_nid, cache_kva);
}

void __victim_flush_func(struct victim_flush_job *job)
{
	bool wait = job->wait;
	struct completion *done = &job->done;
	struct pcache_victim_meta *victim = job->victim;

	PCACHE_BUG_ON_VICTIM(!VictimHasdata(victim) || !VictimAllocated(victim), victim);
	PCACHE_BUG_ON_VICTIM(VictimFlushed(victim) || VictimWriteback(victim), victim);
	PCACHE_BUG_ON_VICTIM(!VictimWaitflush(victim), victim);

	__SetVictimWriteback(victim);
	victim_flush_one(victim);
	inc_pcache_event(PCACHE_VICTIM_FLUSH_FINISHED_DIRTY);
	__ClearVictimWriteback(victim);

	__ClearVictimWaitflush(victim);
	/*
	 * Once this flag is set,
	 * this victim can be an eviction candidate.
	 */
	SetVictimFlushed(victim);

	/*
	 * victim_finish_insert has grabbed 1 ref prior the job was
	 * submitted. Here, we must have a ref > 0. If the victim
	 * has back fill pcached already, this put will lead to free.
	 */
	put_victim(victim);

	if (unlikely(wait))
		complete(done);
	kfree(job);
}

/*
 * Stead a victim flush job from the pending queue.
 * Return NULL if we failed.
 */
struct victim_flush_job *__steal_victim_flush_job(void)
{
	struct victim_flush_job *job = NULL;

	spin_lock(&victim_flush_lock);
	if (unlikely(!list_empty(&victim_flush_queue))) {
		job = list_entry(victim_flush_queue.next, struct victim_flush_job, next);
		__dequeue_victim_flush_job(job);
	}
	spin_unlock(&victim_flush_lock);
	return job;
}

static int victim_flush_async(void *unused)
{
	if (pin_current_thread())
		panic("Fail to pin victim flush");

	for (;;) {
		while (!nr_flush_queue_jobs())
			cpu_relax();

		spin_lock(&victim_flush_lock);
		while (!list_empty(&victim_flush_queue)) {
			struct victim_flush_job *job;

			job = list_entry(victim_flush_queue.next,
					 struct victim_flush_job, next);
			__dequeue_victim_flush_job(job);
			spin_unlock(&victim_flush_lock);

			__victim_flush_func(job);

			spin_lock(&victim_flush_lock);
		}
		spin_unlock(&victim_flush_lock);
	}
	return 0;
}

/* Has to be called after kthreadd is running */
void __init victim_cache_post_init(void)
{
	victim_flush_thread = kthread_run(victim_flush_async, NULL, "kvictim_flushd");
	if (IS_ERR(victim_flush_thread))
		panic("Fail to create victim flush thread!");
}
