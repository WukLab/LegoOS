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
#include <lego/kernel.h>
#include <lego/jiffies.h>
#include <processor/pcache.h>
#include <processor/processor.h>

/*
 * pcache in the lru_list have refcount 1
 * this means it can be freed while we walk through the list
 * recall linux's free/lru code
 */

struct pcache_meta *evict_find_line_lru(struct pcache_set *pset)
{
	return NULL;
}

/*
 * Callback function for the sweep thread
 */
void sweep_pset_lru(struct pcache_set *pset)
{

}
