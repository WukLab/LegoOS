/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MEMORY_REPLICA_H_
#define _LEGO_MEMORY_REPLICA_H_

#include <lego/atomic.h>
#include <lego/kernel.h>
#include <lego/hashtable.h>
#include <memory/replica_types.h>

struct lego_task_struct;

struct replica_struct {
	unsigned int			nr_log;
	struct replica_log		*log;

	/* How many batch flush to storage happened */
	atomic_t			nr_batch_flush;

	/* How many logs has been created */
	atomic_t			nr_created;
} ____cacheline_aligned;

int __must_check alloc_lego_task_struct_replica(struct lego_task_struct *p);
void free_lego_task_struct_replica(struct lego_task_struct *p);

#endif /* _LEGO_MEMORY_REPLICA_H_ */
