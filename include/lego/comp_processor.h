/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_COMP_PROCESSOR_H_
#define _LEGO_COMP_PROCESSOR_H_

#include <lego/sched.h>
#include <lego/signal.h>
#include <generated/unistd_64.h>
#include <lego/comp_common.h>	/* must come at last */

#define DEF_MEM_HOMENODE 1
#define DEF_NET_TIMEOUT	 10	/* second */

#ifdef CONFIG_COMP_PROCESSOR
void __init processor_component_init(void);
int __init pcache_range_register(u64 start, u64 size);
#else
static inline void processor_component_init(void) { }
static inline int pcache_range_register(u64 start, u64 size)
{
	return 0;
}
#endif

int do_execve(const char *filename,
	      const char * const *argv,
	      const char * const *envp);

#endif /* _LEGO_COMP_PROCESSOR_H_ */
