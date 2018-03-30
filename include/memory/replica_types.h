/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Generic definitions about memory replication
 * This file is shared by both memory manager and storage manager.
 */

#ifndef _LEGO_MEMORY_REPLICA_TYPES_H_
#define _LEGO_MEMORY_REPLICA_TYPES_H_

#include <processor/pcache_config.h>

#define REPLICA_HASH_TABLE_SIZE_BIT	(10)

struct replica_log_data {
	char	data[PCACHE_LINE_SIZE];
} __attribute__((packed));

struct replica_log_meta {
	unsigned int	flags;
	/*
	 * Starts from 0
	 * marks the @idx'th entry of @pid's log
	 */
	unsigned int	idx;
	unsigned int	pid;
	unsigned long	user_vaddr;
	unsigned int	csum;
	unsigned int	nid_processor;
	unsigned int	nid_memory;
} __attribute__((packed)) __attribute__((aligned(8)));

struct replica_log {
	struct replica_log_data		data;
	struct replica_log_meta		meta;
} __attribute__((packed));

/* Log meta flags */
#define REPLICA_LOG_CSUM	0x1

static inline bool replica_log_has_csum(struct replica_log *log)
{
	if (log->meta.flags & REPLICA_LOG_CSUM)
		return true;
	return false;
}

static inline void set_replica_log_has_csum(struct replica_log *log)
{
	log->meta.flags |= REPLICA_LOG_CSUM;
}

#endif /* _LEGO_MEMORY_REPLICA_TYPES_H_ */
