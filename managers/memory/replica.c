/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/kernel.h>
#include <lego/slab.h>
#include <lego/hashtable.h>
#include <lego/spinlock.h>
#include <lego/comp_memory.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/task.h>

/*
 * This determines how many log entries
 * are allocated for
 */
unsigned int mem_sysctl_nr_log = 64;

int __must_check alloc_lego_task_struct_replica(struct lego_task_struct *p)
{
	struct replica_struct *replica;
	struct replica_log *log;
	unsigned int nr_log;

	nr_log = mem_sysctl_nr_log;
	log = kzalloc(nr_log * sizeof(*log), GFP_KERNEL);
	if (!log)
		return -ENOMEM;

	replica = &p->replica;
	replica->nr_log = nr_log;
	replica->log = log;

	return 0;
}

void free_lego_task_struct_replica(struct lego_task_struct *p)
{
	struct replica_struct *replica = &p->replica;

	if (replica->log)
		kfree(replica->log);
}
