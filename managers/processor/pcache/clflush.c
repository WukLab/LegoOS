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
#include <lego/comp_processor.h>
#include <processor/pcache.h>

#ifdef CONFIG_DEBUG_PCACHE_FLUSH
#define clflush_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
static inline void clflush_debug(const char *fmt, ...) { }
#endif

static int __pcache_flush_one(struct pcache_meta *pcm,
			      struct pcache_rmap *rmap, void *arg)
{
	int *nr_flushed = arg;
	int ret_len, reply;
	struct task_struct *tsk = rmap->owner;
	unsigned long user_va = rmap->address;
	void *pcache_kva;
	struct p2m_flush_payload *payload;

	payload = kmalloc(sizeof(*payload), GFP_KERNEL);
	if (!payload)
		return PCACHE_RMAP_FAILED;

	payload->pid = tsk->tgid;
	payload->user_va = user_va & PCACHE_LINE_MASK;

	pcache_kva = pcache_meta_to_kva(pcm);
	memcpy(payload->pcacheline, pcache_kva, PCACHE_LINE_SIZE);

	clflush_debug("I tgid:%u user_va:%#lx pcache_kva:%p",
		payload->pid, payload->user_va, pcache_kva);

	ret_len = net_send_reply_timeout(DEF_MEM_HOMENODE, P2M_LLC_FLUSH,
			payload, sizeof(*payload), &reply, sizeof(reply),
			false, DEF_NET_TIMEOUT);

	clflush_debug("O tgid:%u user_va:%#lx pcache_kva:%p reply:%d %s",
		payload->pid, payload->user_va, pcache_kva, reply, perror(reply));

	kfree(payload);

	if (unlikely(ret_len < sizeof(reply)))
		return PCACHE_RMAP_FAILED;

	if (unlikely(reply)) {
		dump_pcache_meta(pcm, FUNC);
		pr_err("%s(): %s\n", FUNC, perror(reply));
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
