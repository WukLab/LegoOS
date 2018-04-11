/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/time.h>
#include <lego/sched.h>
#include <lego/kthread.h>
#include <lego/jiffies.h>
#include <lego/fit_ibapi.h>
#include <lego/comp_common.h>
#include <processor/distvm.h>
#include <processor/zerofill.h>

#define NR_ZEROFILL_WORK	(1024)

/*
 * In order to avoid runtime allocation of zerofill_work,
 * we define a prepopulated work map ring. During runtime,
 * the HEAD element will be used for submitting new work.
 *
 * Since the allocation part can be called by multiple thread
 * concurrently, HEAD should be atomic. This is different from
 * our memory polling thread, where the polling thread is the
 * only thread will do allocate.
 */
static atomic_long_t HEAD;

/*
 * TAIL is only incremented by the async flush thread.
 * So it can be a simple long, which can save us some cost.
 */
static long TAIL;
static struct zerofill_work zerofill_work_map_ring[NR_ZEROFILL_WORK];
static struct task_struct *zerofill_task;

static inline struct zerofill_work *idx_to_zerofill_work(int idx)
{
	BUG_ON(idx >= NR_ZEROFILL_WORK);
	return zerofill_work_map_ring + idx;
}

/*
 * Allocate the next avaiable work structure.
 * This will be called by multiple threads concurrently.
 */
static __always_inline inline struct zerofill_work *alloc_zerofill_work(void)
{
	long idx;
	struct zerofill_work *zw;
	unsigned long wait_start = jiffies;

	/*
	 * Atomically read the _current_ HEAD and increment it.
	 * This is SMP safe without a lock.
	 */
	idx = atomic_long_fetch_add(1, &HEAD);
	idx = idx % NR_ZEROFILL_WORK;
	zw = idx_to_zerofill_work(idx);

	/*
	 * Overflowed?
	 * We have prepared a very large cushion. If this case got
	 * triggered, and the NR_ZEROFILL_WORK is already very large,
	 * then it is more likely to be a BUG in the flush thread.
	 */
	while (unlikely(ZerofillUsed(zw) || ZerofillFlush(zw))) {
		pr_info("zerofill: WARNING overflow detected!\n");
		if (unlikely(time_after(jiffies, wait_start + 30 * HZ)))
			panic("Either BUG, or increase NR_ZEROFILL_WORK.");
	}
	return zw;
}

void submit_zerofill_notify_work(struct task_struct *p,
				 unsigned long address, unsigned long flags)
{
	struct zerofill_work *zw;

	zw = alloc_zerofill_work();
	zw->pid = p->pid;
	zw->tgid = p->tgid;
	zw->fault_flags = flags;
	zw->fault_user_vaddr = address;
	zw->memory_nid = get_memory_node(p, address);

	/* Inform async flush thread */
	SetZerofillUsed(zw);
}

static void do_zerofill_work(struct zerofill_work *zw)
{
	struct p2m_zerofill_msg msg;
	int dst_nid, reply;

	fill_common_header(&msg, P2M_PCACHE_ZEROFILL);
	msg.pid = zw->pid;
	msg.tgid = zw->tgid;
	msg.flags = zw->fault_flags;
	msg.missing_vaddr = zw->fault_user_vaddr;
	dst_nid = zw->memory_nid;

	SetZerofillFlush(zw);
	ibapi_send_reply_timeout(dst_nid, &msg, sizeof(msg),
				 &reply, sizeof(reply), false, DEF_NET_TIMEOUT);
	ClearZerofillFlush(zw);
}

/*
 * Once HEAD incremented, polling thread will get next pending work.
 * But by that time the zerofill_work may not be filled completely.
 * So, wait until submit_zerofill_work() finished.
 */
static __always_inline void wait_work_usable(struct zerofill_work *zw)
{
	unsigned long wait_start = jiffies;

	while (unlikely(!ZerofillUsed(zw))) {
		if (unlikely(time_after(jiffies, wait_start + 30 * HZ)))
			panic("where is the set zerofill usable?");
	}
}

/*
 * Get the first work pending. Also increment TAIL to next position.
 * This is only called by a single thread.
 */
static __always_inline struct zerofill_work *next_pending_work(void)
{
	long idx;
	struct zerofill_work *zw;

	idx = TAIL % NR_ZEROFILL_WORK;
	TAIL++;
	zw = idx_to_zerofill_work(idx);

	wait_work_usable(zw);
	return zw;
}

/*
 * A mod (%) will not do here. Both TAIL and HEAD increment without reset.
 * If TAIL is smaller than HEAD, it means there are works pending.
 */
static inline bool has_pending_work(void)
{
	return TAIL < atomic_long_read(&HEAD);
}

static int zerofill_async_func(void *_unused)
{
	struct zerofill_work *zw;

	pr_info("zerofill: async notify CPU%d UP", smp_processor_id());

	while (1) {
		while (!has_pending_work()) {
			cpu_relax();
			continue;
		}

		/* Handle one work at a time */
		zw = next_pending_work();
		do_zerofill_work(zw);
		ClearZerofillUsed(zw);
	}
	BUG();
	return 0;
}

int pcache_zerofill_notify_init(void)
{
	zerofill_task = kthread_run(zerofill_async_func, NULL, "kzerofilld");
	if (!zerofill_task)
		panic("Fail to create zerofilld\n");
	return 0;
}
