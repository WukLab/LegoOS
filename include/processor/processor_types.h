/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file is included by sched.h
 * So we can not put anything other than self-contained definitions here.
 */

#ifndef _LEGO_PROCESSOR_PROCESSOR_TYPES_H_
#define _LEGO_PROCESSOR_PROCESSOR_TYPES_H_

#include <lego/types.h>
#include <lego/atomic.h>
#include <processor/vnode_types.h>

#ifdef CONFIG_COMP_PROCESSOR

/*
 * If you add anything to structure, please check if these fields
 * need to be initlizaed in the init_task.c
 */
struct processor_manager {
	/*
	 * The memory home node. This is the node
	 * where loading happens and serves mmap related syscalls.
	 */
	int		home_node;

	/*
	 * The replica memory node. This is the node
	 * where serves memory replication of this process.
	 *
	 * If distributed vma is configured, this node will
	 * not be used. Instead, it will be stored in the mnode
	 * array. Each VMA_GRANULARITRY has its own replica node.
	 */
	int		replica_node;

#ifdef CONFIG_CHECKPOINT
	atomic_t	process_barrier;
#endif

#ifdef CONFIG_GSM
	int		pgcache_node;
	int		storage_node;
#endif

	struct vnode_struct *virtual_node;
};

#define UNSET_HOME_NODE		(INT_MAX)
#define UNSET_REPLICA_NODE	(INT_MAX)
#define UNSET_PGCACHE_NODE	(INT_MAX)
#define UNSET_STORAGE_NODE	(INT_MAX)

#endif /* COMP_PROSESSOR */

#endif /* _LEGO_PROCESSOR_PROCESSOR_TYPES_H_ */
