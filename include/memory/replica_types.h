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

#include <asm/bitops.h>
#include <processor/pcache_config.h>

#define REPLICA_HASH_TABLE_SIZE_BIT	(10)

struct replica_log_meta {
	unsigned int	pid;
	unsigned int	vnode_id;

	unsigned int	nid_memory;
	unsigned int	nid_processor;

	unsigned long	user_va;

	unsigned int	flags;
	unsigned int	csum;
} __attribute__((packed)) __attribute__((aligned(8)));

struct replica_log {
	struct replica_log_meta		meta;
	char				data[PCACHE_LINE_SIZE];
} __attribute__((packed));

static inline int replica_get_hash_key(unsigned int pid, unsigned int vnode_id)
{
	return pid * 100 + vnode_id * 1000;
}

/*
 * valid: this log has been filled
 * csum: this log has csum computed and attached in meta
 */
enum replica_log_meta_flags {
	REPLICA_LOG_META_valid,
	REPLICA_LOG_META_csum,

	NR_REPLICA_LOG_META_FLAGS,
};

#define TEST_REPLICA_LOG_META_FLAGS(uname, lname)			\
static inline int ReplicaLog##uname(const struct replica_log *p)	\
{									\
	return test_bit(REPLICA_LOG_META_##lname,			\
			(unsigned long *)&(p->meta.flags));		\
}

#define SET_REPLICA_LOG_META_FLAGS(uname, lname)			\
static inline void SetReplicaLog##uname(struct replica_log *p)		\
{									\
	set_bit(REPLICA_LOG_META_##lname,				\
			(unsigned long *)&(p->meta.flags));		\
}

#define CLEAR_REPLICA_LOG_META_FLAGS(uname, lname)			\
static inline void ClearReplicaLog##uname(struct replica_log *p)	\
{									\
	clear_bit(REPLICA_LOG_META_##lname,				\
			(unsigned long *)&(p->meta.flags));		\
}

#define REPLICA_LOG_META_FLAGS(uname, lname)				\
	TEST_REPLICA_LOG_META_FLAGS(uname, lname)			\
	SET_REPLICA_LOG_META_FLAGS(uname, lname)			\
	CLEAR_REPLICA_LOG_META_FLAGS(uname, lname)

REPLICA_LOG_META_FLAGS(Valid, valid)
REPLICA_LOG_META_FLAGS(Csum, csum)

/*
 * Primary Memory VMA Replication
 */
enum replica_vma_action {
	REPLICATE_MMAP = 1,
	REPLICATE_MUNMAP,
	REPLICATE_BRK,
	REPLICATE_MREMAP,

	NR_REPLICATE_TYPES,
};

struct replica_vma_log {
	unsigned int	pid;
	unsigned int	vnode_id;

	unsigned int		action;
	unsigned long		new_addr;
	unsigned long		new_len;
	unsigned long		old_addr;
	unsigned long		old_len;
} __attribute__((packed)) __attribute__((aligned(8)));

#endif /* _LEGO_MEMORY_REPLICA_TYPES_H_ */
