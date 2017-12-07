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
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/syscalls.h>
#include <lego/jiffies.h>
#include <processor/pcache.h>
#include <processor/processor.h>

#ifdef CONFIG_DEBUG_PCACHE_FLUSH
#define clflush_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
static inline void clflush_debug(const char *fmt, ...) { }
#endif

static int __clflush_one(struct task_struct *tsk, unsigned long user_va,
			 void *cache_addr, void *caller)
{
	struct p2m_flush_payload *payload;
	int ret_len, reply;
	int retval;

	payload = kmalloc(sizeof(*payload), GFP_KERNEL);
	if (!payload)
		return -ENOMEM;

	payload->pid = tsk->tgid;
	payload->user_va = user_va & PCACHE_LINE_MASK;
	memcpy(payload->pcacheline, cache_addr, PCACHE_LINE_SIZE);

	clflush_debug("I tgid:%u user_va:%#lx cache_kva:%p caller: %pS",
		payload->pid, payload->user_va, cache_addr, caller);

	ret_len = net_send_reply_timeout(tsk->home_node, P2M_LLC_FLUSH,
			payload, sizeof(*payload), &reply, sizeof(reply),
			false, DEF_NET_TIMEOUT);

	clflush_debug("O tgid:%u user_va:%#lx cache_kva:%p reply:%d %s",
		payload->pid, payload->user_va, cache_addr, reply, perror(reply));

	if (unlikely(ret_len < sizeof(reply))) {
		retval = -EFAULT;
		goto out;
	}

	if (unlikely(reply)) {
		pr_err("%s(): %s\n", FUNC, perror(reply));
		retval = reply;
		goto out;
	}

	retval = 0;
out:
	kfree(payload);
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
	return __clflush_one(tsk, user_va, cache_addr,
			__builtin_return_address(0));
}

static int __pcache_flush_one(struct pcache_meta *pcm,
			      struct pcache_rmap *rmap, void *arg)
{
	int *nr_flushed = arg;
	int ret;

	ret = clflush_one(rmap->owner, rmap->address, pcache_meta_to_kva(pcm));
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

	SetPcacheWriteback(pcm);
	rmap_walk(pcm, &rwc);
	ClearPcacheWriteback(pcm);

	return 0;
}
