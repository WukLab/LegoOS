/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/kernel.h>
#include <lego/tracepoint.h>
#include <processor/pcache.h>

#define __def_pcacheflag_names					\
	{1UL << PC_locked,		"locked"	},	\
	{1UL << PC_allocated,		"allocated"	},	\
	{1UL << PC_valid,		"valid"		},	\
	{1UL << PC_dirty,		"dirty"		},	\
	{1UL << PC_writeback,		"writeback"	}

const struct trace_print_flags pcacheflag_names[] = {
	__def_pcacheflag_names,
	{0, NULL}
};

void dump_pcache_meta(struct pcache_meta *pcm, const char *reason)
{
	pr_debug("pcache:%p mapcount:%d flags:(%pGc)\n",
		pcm, atomic_read(&pcm->mapcount), &pcm->bits);
	if (reason)
		pr_debug("pcache dumped because: %s\n", reason);
}
