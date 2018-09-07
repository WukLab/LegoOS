/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/smp.h>
#include <lego/wait.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/hash.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/profile.h>
#include <lego/syscalls.h>
#include <lego/jiffies.h>
#include <lego/fit_ibapi.h>
#include <processor/pcache.h>
#include <processor/distvm.h>
#include <processor/processor.h>
#include <processor/replication.h>

#ifdef CONFIG_DEBUG_PCACHE_FLUSH
#define clflush_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
static inline void clflush_debug(const char *fmt, ...) { }
#endif

static struct p2m_flush_msg *clflush_msg_array;

DEFINE_PROFILE_POINT(pcache_flush_net)

/*
 * Ultimate flush function.
 * Caller needs to provide all necessary information.
 * And those information MUST NOT be pointers. Because this function is normally
 * executed async from the normal code path. Task/mm structure may be freed already.
 *
 * Replication is done the at the end, if configured.
 *
 * TODO:
 * Instead of having a per-cpu message array and doing a memcpy,
 * we should use IB sg list to send both metadate and in-place cache data out.
 */
void __clflush_one(pid_t tgid, unsigned long user_va,
		   unsigned int m_nid, unsigned int rep_nid, void *cache_addr)
{
	int reply, cpu;
	struct p2m_flush_msg *msg;
	PROFILE_POINT_TIME(pcache_flush_net)

	/*
	 * Okay the trick here is: we are using sync network API
	 * which means each CPU should only have 1 outstanding request.
	 * A static message array will work.
	 */
	cpu = get_cpu();
	msg = &clflush_msg_array[cpu];

	/* Fill message */
	fill_common_header(msg, P2M_PCACHE_FLUSH);
	msg->pid = tgid;
	msg->user_va = user_va & PCACHE_LINE_MASK;
	memcpy(msg->pcacheline, cache_addr, PCACHE_LINE_SIZE);
	barrier();

	clflush_debug("I m_nid:%d tgid:%u user_va:%#lx cache_kva:%p",
		m_nid, msg->pid, msg->user_va, cache_addr);

	/* Network */
	PROFILE_START(pcache_flush_net);
	ibapi_send_reply_timeout(m_nid, msg, sizeof(*msg),
				 &reply, sizeof(reply), false, DEF_NET_TIMEOUT);
	PROFILE_LEAVE(pcache_flush_net);
	clflush_debug("O tgid:%u user_va:%#lx cache_kva:%p reply:%d %s",
		msg->pid, msg->user_va, cache_addr, reply, perror(reply));

	/* Counting */
	inc_pcache_event(PCACHE_CLFLUSH);
	inc_pcache_event_cond(PCACHE_CLFLUSH_FAIL, !!reply);

	/*
	 * Replica this dirty cache line to secondary
	 * memory component. If replication is enabled.
	 */
	replicate(tgid, user_va, m_nid, rep_nid, cache_addr);

	put_cpu();
}

/*
 * @tsk: the task this cache line belongs to
 * @user_va: the user virtual address associated with this line
 * @cache_addr: the kernel virtual address of the cache line
 *              that is going to be flushed.
 *
 * HACK!!! Make sure at the time of calling, tsk and tsk->mm are still alive!
 * Because this function will be called in ASYNC code path, and we DO NOT have
 * any further checking against liveness.
 */
void clflush_one(struct task_struct *tsk, unsigned long user_va, void *cache_addr)
{
	unsigned int m_nid, rep_nid;

	m_nid = get_memory_node(tsk, user_va);
	rep_nid = get_replica_node_by_addr(tsk, user_va);
	__clflush_one(tsk->tgid, user_va, m_nid, rep_nid, cache_addr);
}

static int __pcache_flush_one(struct pcache_meta *pcm,
			      struct pcache_rmap *rmap, void *arg)
{
	int *nr_flushed = arg;

	clflush_one(rmap->owner_process, rmap->address,
		    pcache_meta_to_kva(pcm));

	(*nr_flushed)++;
	return PCACHE_RMAP_AGAIN;
}

/**
 * pcache_flush_one
 * @pcm: pcache line to flush
 *
 * This function will flush one pcache line back to backing memory components.
 * During flush, @pcm is locked and marked as Writeback. If flush involes
 * multiple memory components, we need to take care of.
 * @pcm must be locked on entry.
 */
int pcache_flush_one(struct pcache_meta *pcm)
{
	int nr_flushed = 0;
	struct rmap_walk_control rwc = {
		.arg = &nr_flushed,
		.rmap_one = __pcache_flush_one,
	};

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);
	PCACHE_BUG_ON_PCM(PcacheWriteback(pcm), pcm);

	/*
	 * XXX:
	 * Currently only the eviction will call flush, later we may
	 * add other things such as process exit, chkpoint etc.
	 * 
	 * So, for now add this check to catch bugs.
	 */
	PCACHE_BUG_ON_PCM(!PcacheReclaim(pcm), pcm);

	SetPcacheWriteback(pcm);
	rmap_walk(pcm, &rwc);
	ClearPcacheWriteback(pcm);

	return 0;
}

void __init init_pcache_clflush_buffer(void)
{
	clflush_msg_array = kmalloc(sizeof(*clflush_msg_array) * nr_cpus, GFP_KERNEL);
	if (!clflush_msg_array)
		panic("Unable to allocate clflush message array");

	pr_info("%s(): clflush array at %p, nr_entries: %d\n",
		__func__, clflush_msg_array, nr_cpus);
}
