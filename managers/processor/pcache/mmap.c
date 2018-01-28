/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/memblock.h>

#include <processor/pcache.h>
#include <processor/processor.h>

/*
 * Called when a process exit
 * Cleanup all pcache lines
 *
 * TODO:
 * Anonymous: just free
 * File-backed: flush back
 *
 * Be careful against pcache eviction
 */
void exit_pcache_mmap(struct mm_struct *mm)
{

}
