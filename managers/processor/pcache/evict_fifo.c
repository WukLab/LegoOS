/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/kernel.h>
#include <processor/pcache.h>
#include <processor/processor.h>

struct pcache_meta *evict_find_line_fifo(struct pcache_set *pset)
{
	panic("pcache/eviction: FIFO not implemented!");
	return NULL;
}
