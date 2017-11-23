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

#include <asm/io.h>

#include <processor/include/pcache.h>


/**
 * pcache_flush_one
 * @pcm: pcache line to flush
 *
 * This function will flush one pcache line back
 * to backing memory components. We only do the real
 * flush work here. Other protection issues need to
 * be taken care of before calling this function!
 */
int pcache_flush_one(struct pcache_meta *pcm)
{
	return 0;
}
