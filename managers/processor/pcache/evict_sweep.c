/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Background sweep threads for eviction selection
 * Dirty work is done by the algorithm-specific callback.
 */

#include <lego/mm.h>
#include <lego/smp.h>
#include <lego/wait.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/hash.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>
#include <lego/kthread.h>
#include <lego/profile.h>
#include <processor/pcache.h>
#include <processor/processor.h>

static struct task_struct *sweep_thread;

static int kevict_sweepd(void *unused)
{
	if (pin_current_thread())
		panic("Fail to pin evict sweepd");

	kevict_sweepd_lru();
	return 0;
}

int __init evict_sweep_init(void)
{
	sweep_thread = kthread_run(kevict_sweepd, NULL, "kevict_sweepd");
	if (IS_ERR(sweep_thread))
		return PTR_ERR(sweep_thread);
	return 0;
}
