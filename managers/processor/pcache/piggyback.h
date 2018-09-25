/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _PROCESSOR_PCACHE_PIGGYBACK_H_
#define _PROCESSOR_PCACHE_PIGGYBACK_H_

extern DEFINE_PER_CPU(struct pcache_meta *, piggybacker);

static inline void set_per_cpu_piggybacker(struct pcache_meta *pcm)
{
	struct pcache_meta *old;

	old = this_cpu_read(piggybacker);
	if (likely(!old)) {
		this_cpu_write(piggybacker, pcm);
		SetPcachePiggybackCached(pcm);
		return;
	}

	/*
	 * One cpu is only allowed to set once.
	 * The one who evicted this must have pcache miss on remote.
	 */
	dump_pcache_meta(old, "override");
	BUG();
}

/* If we grabbed one, the per-cpu array entry will be reset */
static inline struct pcache_meta *get_per_cpu_piggybacker(void)
{
	struct pcache_meta *pcm;

	pcm = this_cpu_read(piggybacker);
	if (pcm)
		this_cpu_write(piggybacker, NULL);
	return pcm;
}

#endif /* _PROCESSOR_PCACHE_PIGGYBACK_H_ */
