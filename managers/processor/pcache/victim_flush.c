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

struct victim_flush_info {
	struct pcache_victim_meta *victim;
	struct completion done;
	bool wait;
	struct list_head list;
};

static DEFINE_SPINLOCK(victim_flush_lock);
static LIST_HEAD(victim_flush_list);
static struct task_struct *victim_flush_thread;

int victim_submit_flush(struct pcache_victim_meta *victim, bool wait)
{
	struct victim_flush_info *info;

	PCACHE_BUG_ON_VICTIM(VictimFlushed(victim) || VictimWriteback(victim) ||
			    !VictimHasdata(victim) || !VictimAllocated(victim),
			    victim);

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;
	info->victim = victim;
	info->wait = wait;
	if (unlikely(wait))
		init_completion(&info->done);

	spin_lock(&victim_flush_lock);
	list_add_tail(&info->list, &victim_flush_list);
	spin_unlock(&victim_flush_lock);

	/* flush thread will free info */
	wake_up_process(victim_flush_thread);
	if (unlikely(wait))
		wait_for_completion(&info->done);
	return 0;
}

static int victim_flush_one(struct pcache_victim_meta *victim)
{
	void *cache_kva;
	int nr_flushed = 0;

	cache_kva = pcache_victim_to_kva(victim);
	spin_lock(&victim->lock);
	while (!list_empty(&victim->hits)) {
		struct pcache_victim_hit_entry *hit;
		int ret;

		hit = list_entry(victim->hits.next,
				struct pcache_victim_hit_entry, next);
		list_del_init(&hit->next);
		spin_unlock(&victim->lock);

		ret = clflush_one(hit->owner, hit->address, cache_kva);
		if (likely(!ret))
			nr_flushed++;

		spin_lock(&victim->lock);
	}
	spin_unlock(&victim->lock);

	return nr_flushed;
}

static void __victim_flush_func(struct victim_flush_info *info)
{
	bool wait = info->wait;
	struct completion *done = &info->done;
	struct pcache_victim_meta *victim = info->victim;

	PCACHE_BUG_ON_VICTIM(VictimFlushed(victim) || VictimWriteback(victim)
			    !VictimHasdata(victim) || !VictimAllocated(victim),
			    victim);

	SetVictimWriteback(victim);
	victim_flush_one(victim);
	ClearVictimWriteback(victim);

	/*
	 * Once this flag is set,
	 * this victim can be an eviction candidate.
	 */
	SetVictimFlushed(victim);

	if (unlikely(wait))
		complete(done);
	kfree(info);
}

static int victim_flush_func(void *unused)
{
	set_cpus_allowed_ptr(current, cpu_active_mask);

	for (;;) {
		/* Sleep until someone wakes me up before september ends */
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (list_empty(&victim_flush_list))
			schedule();
		__set_current_state(TASK_RUNNING);

		spin_lock(&victim_flush_lock);
		while (!list_empty(&victim_flush_list)) {
			struct victim_flush_info *info;

			info = list_entry(victim_flush_list.next,
					  struct victim_flush_info, list);
			list_del_init(&info->list);
			spin_unlock(&victim_flush_lock);

			__victim_flush_func(info);

			spin_lock(&victim_flush_lock);
		}
		spin_unlock(&victim_flush_lock);
	}
	return 0;
}

/* Has to be called after kthreadd is running */
void __init victim_cache_post_init(void)
{
	victim_flush_thread = kthread_run(victim_flush_func, NULL, "victimd");
	if (IS_ERR(victim_flush_thread))
		panic("Fail to create victim flush thread!");
}
