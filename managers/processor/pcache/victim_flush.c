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

void wake_up_victim_flushd(void)
{
	wake_up_process(victim_flush_thread);
}

/*
 * Submit a victim cache line to flush queue.
 * @wait: true if you want to wait for completion
 */
int victim_submit_flush(struct pcache_victim_meta *victim, bool wait)
{
	struct victim_flush_job *job;

	PCACHE_BUG_ON_VICTIM(!VictimHasdata(victim) || !VictimAllocated(victim), victim);
	PCACHE_BUG_ON_VICTIM(VictimFlushed(victim) || VictimWriteback(victim) ||
			     VictimWaitflush(victim), victim);

	SetVictimWaitflush(victim);

	/*
	 * Make sure this victim will not go away during flush.
	 * Eviction won't touch it cause Flushed bit is not.
	 * But victim fill pcache path will put it once hit finished.
	 */
	get_victim(victim);

	job = kmalloc(sizeof(*job), GFP_KERNEL);
	if (WARN_ON(!job))
		return -ENOMEM;
	job->victim = victim;
	job->wait = wait;
	if (unlikely(wait))
		init_completion(&job->done);

	enqueue_victim_flush_job(job);

	/* Update counter */
	inc_pcache_event(PCACHE_VICTIM_FLUSH_SUBMITTED);

	/* flush thread will free job */
	wake_up_process(victim_flush_thread);
	if (unlikely(wait))
		wait_for_completion(&job->done);

	return 0;
}

/*
 * Return number of succeed clflush
 * It can be 0, if the address belonged area was unmapped
 */
static int victim_flush_one(struct pcache_victim_meta *victim)
{
	void *cache_kva;
	int ret, nr_flushed = 0;
	struct pcache_victim_hit_entry *entry;

	cache_kva = pcache_victim_to_kva(victim);

	/*
	 * We don't need acquire the spinlock to walk through
	 * the list at this point: 1) Eviction won't take this
	 * victim cause Flushed is not set. 2) Insertion only
	 * happens once and it already happened.
	 */
	list_for_each_entry(entry, &victim->hits, next) {
		ret = clflush_one(entry->owner, entry->address, cache_kva);
		if (likely(!ret))
			nr_flushed++;
	}

	return nr_flushed;
}

static void __victim_flush_func(struct victim_flush_job *job)
{
	bool wait = job->wait;
	struct completion *done = &job->done;
	struct pcache_victim_meta *victim = job->victim;

	PCACHE_BUG_ON_VICTIM(!VictimHasdata(victim) || !VictimAllocated(victim), victim);
	PCACHE_BUG_ON_VICTIM(VictimFlushed(victim) || VictimWriteback(victim), victim);
	PCACHE_BUG_ON_VICTIM(!VictimWaitflush(victim), victim);

	SetVictimWriteback(victim);
	victim_flush_one(victim);
	ClearVictimWriteback(victim);

	ClearVictimWaitflush(victim);
	/*
	 * Once this flag is set,
	 * this victim can be an eviction candidate.
	 */
	SetVictimFlushed(victim);

	/* Paired when job submitted */
	put_victim(victim);

	if (unlikely(wait))
		complete(done);
	kfree(job);

	/* Update counter */
	inc_pcache_event(PCACHE_VICTIM_FLUSH_FINISHED);
}

/*
 * Synchronously flush victim cache lines
 * return number of lines be flushed at this run.
 */
int victim_flush_sync(void)
{
	int nr_flushed = 0;

	inc_pcache_event(PCACHE_VICTIM_FLUSH_SYNC);

	/*
	 * Don't release the lock in the middle
	 * We may end up flushing for more than we wanted.
	 */
	spin_lock(&victim_flush_lock);
	while (!list_empty(&victim_flush_queue)) {
		struct victim_flush_job *job;

		job = list_entry(victim_flush_queue.next,
				 struct victim_flush_job, next);
		__dequeue_victim_flush_job(job);

		__victim_flush_func(job);
		nr_flushed++;
	}
	spin_unlock(&victim_flush_lock);

	return nr_flushed;
}

static int victim_flush_async(void *unused)
{
	set_cpus_allowed_ptr(current, cpu_active_mask);

	for (;;) {
		/* Sleep until someone wakes me up before september ends */
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (list_empty(&victim_flush_queue))
			schedule();
		__set_current_state(TASK_RUNNING);

		inc_pcache_event(PCACHE_VICTIM_FLUSH_ASYNC_RUN);

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
