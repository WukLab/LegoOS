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

DEFINE_PROFILE_POINT(pcache_flush)

static int __clflush_one(struct task_struct *tsk, unsigned long user_va,
			 void *cache_addr, void *caller)
{
	struct p2m_flush_msg *msg;
	int ret_len, reply;
	int retval;
	int dst_nid;
	PROFILE_POINT_TIME(pcache_flush)

	msg = kmalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	fill_common_header(msg, P2M_PCACHE_FLUSH);
	msg->pid = tsk->tgid;
	msg->user_va = user_va & PCACHE_LINE_MASK;
	memcpy(msg->pcacheline, cache_addr, PCACHE_LINE_SIZE);
	dst_nid = get_memory_node(tsk, user_va);

	clflush_debug("I dst_nid:%d tgid:%u user_va:%#lx cache_kva:%p caller: %pS",
		dst_nid, msg->pid, msg->user_va, cache_addr, caller);

	profile_point_start(pcache_flush);
	ret_len = ibapi_send_reply_timeout(dst_nid, msg, sizeof(*msg),
			&reply, sizeof(reply), false, DEF_NET_TIMEOUT);
	profile_point_leave(pcache_flush);

	clflush_debug("O tgid:%u user_va:%#lx cache_kva:%p reply:%d %s",
		msg->pid, msg->user_va, cache_addr, reply, perror(reply));

	if (unlikely(ret_len < sizeof(reply))) {
		retval = -EFAULT;
		goto out;
	}

	if (unlikely(reply)) {
		pr_err("%s(): %s tsk: %d user_va: %#lx\n", FUNC, perror(reply), tsk->pid, user_va);
		retval = reply;
		goto out;
	}

	retval = 0;
out:
	kfree(msg);
	return retval;
}

/*
 * @tsk: the task this cache line belongs to
 * @user_va: the user virtual address associated with this line
 * @cache_addr: the kernel virtual address of the cache line
 *              that is going to be flushed.
 *
 * Return 0 on success, otherwise on failures.
 */
int clflush_one(struct task_struct *tsk, unsigned long user_va,
		void *cache_addr)
{
	int ret;

	inc_pcache_event(PCACHE_CLFLUSH);
	ret = __clflush_one(tsk, user_va, cache_addr, __builtin_return_address(0));

	/*
	 * Replica this dirty cache line to secondary
	 * memory component. If replication is enabled.
	 */
	replicate(tsk, user_va, cache_addr);

	return ret;
}

static int __pcache_flush_one(struct pcache_meta *pcm,
			      struct pcache_rmap *rmap, void *arg)
{
	int *nr_flushed = arg;
	int ret;

	ret = clflush_one(rmap->owner_process, rmap->address,
			  pcache_meta_to_kva(pcm));
	if (ret) {
		dump_pcache_meta(pcm, FUNC);
		dump_pcache_rmap(rmap, FUNC);
		return PCACHE_RMAP_FAILED;
	}

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
	int nr_flushed;
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
