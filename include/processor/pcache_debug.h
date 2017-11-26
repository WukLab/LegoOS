/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROCESSOR_PCACHE_DEBUG_H_
#define _LEGO_PROCESSOR_PCACHE_DEBUG_H_

#include <lego/types.h>
#include <processor/pcache_types.h>

__wsum pcache_line_csum(struct pcache_meta *pcm);
void dump_pcache_meta(struct pcache_meta *pcm, const char *reason);
void dump_pcache_line(struct pcache_meta *pcm, const char *reason);
void dump_pcache_rmap(struct pcache_rmap *);
extern const struct trace_print_flags pcacheflag_names[];

#ifdef CONFIG_DEBUG_PCACHE
#define PCACHE_BUG_ON(cond)		BUG_ON(cond)
#define PCACHE_WARN_ON(cond)		WARN_ON(cond)
#define PCACHE_WARN(cond, format...)	WARN(cond, format)

#define PCACHE_BUG_ON_PCM(cond, pcm)					\
do {									\
	if (unlikely(cond)) {						\
		dump_pcache_meta(pcm,					\
			"PCACHE_BUG_ON_PCM(" __stringify(cond)")");	\
		BUG();							\
	}								\
} while (0)

#else
#define PCACHE_BUG_ON(cond)		do { } while (0)
#define PCACHE_WARN_ON(cond)		do { } while (0)
#define PCACHE_WARN(cond, format...)	do { } while (0)
#define PCACHE_BUG_ON_PCM(cond, pcm)	do { } while (0)
#endif /* CONFIG_DEBUG_PCACHE */

#endif /* _LEGO_PROCESSOR_PCACHE_DEBUG_H_ */
