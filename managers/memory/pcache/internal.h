/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Internal header file of memory pcache handling subsystem
 */

#ifndef _MEMORY_PCACHE_INTERNAL_H_
#define _MEMORY_PCACHE_INTERNAL_H_

#ifdef CONFIG_DEBUG_HANDLE_PCACHE
static DEFINE_RATELIMIT_STATE(pcache_debug_rs,
	DEFAULT_RATELIMIT_INTERVAL, DEFAULT_RATELIMIT_BURST);

#define pcache_debug(fmt, ...)						\
({									\
	if (__ratelimit(&pcache_debug_rs))				\
		pr_debug("%s() cpu%2d " fmt "\n",			\
			__func__, smp_processor_id(), __VA_ARGS__);	\
})
#else
static inline void pcache_debug(const char *fmt, ...) { }
#endif

void do_mmap_prefetch(struct lego_task_struct *p, u64 vaddr,
		      u32 flags, u32 nr_pages);

#endif /* _MEMORY_PCACHE_INTERNAL_H_ */
