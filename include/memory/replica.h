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

struct _replica_padding {
	char x[0];
} ____cacheline_aligned;
#define REPLICA_PADDING(name)	struct _replica_padding name;

struct replica_struct {
	/*
	 * User level pid
	 * vNode ID
	 * Memory ID which serves the Processor
	 * Processor ID which sent the replication request
	 */
	unsigned int			pid;
	unsigned int			vnode_id;
	unsigned int			nid_memory;
	unsigned int			nid_processor;
	unsigned int			hash_key;

	/* Flags defined below */
	unsigned long			flags;

	/*
	 * HEAD points to the first available log slot.
	 * It ranges: [0, nr_log-1]. Protected by @lock.
	 *
	 *        4b     4b
	 *     |opcode|nr_log| .. log ..|
	 *     ^             ^
	 *   flush_msg      log
	 */
	void 				*flush_msg;
	size_t				flush_msg_size;
	unsigned int			nr_log;
	struct replica_log		*log;

	REPLICA_PADDING(_pad1_);

	unsigned int			HEAD;
	spinlock_t			lock;

	REPLICA_PADDING(_pad2_);

	atomic_t			_refcount;

	/* How many batch flush to storage happened */
	atomic_t			nr_batch_flush;

	/* How many logs has been created */
	atomic_t			nr_created;

	struct hlist_node		hlist;
} ____cacheline_aligned;

/*
 * replica_struct->flags
 */

enum replica_struct_flags {
	REPLICA_STRUCT_flushing,

	NR_REPLICA_STRUCT_FLAGS,
};

#define TEST_REPLICA_STRUCT_FLAGS(uname, lname)				\
static inline int Replica##uname(const struct replica_struct *p)	\
{									\
	return test_bit(REPLICA_STRUCT_##lname, &p->flags);		\
}

#define SET_REPLICA_STRUCT_FLAGS(uname, lname)				\
static inline void SetReplica##uname(struct replica_struct *p)		\
{									\
	set_bit(REPLICA_STRUCT_##lname, &p->flags);			\
}

#define CLEAR_REPLICA_STRUCT_FLAGS(uname, lname)			\
static inline void ClearReplica##uname(struct replica_struct *p)	\
{									\
	clear_bit(REPLICA_STRUCT_##lname, &p->flags);			\
}

#define REPLICA_STRUCT_FLAGS(uname, lname)				\
	TEST_REPLICA_STRUCT_FLAGS(uname, lname)				\
	SET_REPLICA_STRUCT_FLAGS(uname, lname)				\
	CLEAR_REPLICA_STRUCT_FLAGS(uname, lname)

REPLICA_STRUCT_FLAGS(Flushing, flushing)

void __put_replica_struct(struct replica_struct *r);

/*
 * refcount helpers
 */

static inline void init_replica_refcount(struct replica_struct *r)
{
	atomic_set(&r->_refcount, 1);
}

static inline void get_replica(struct replica_struct *r)
{
	atomic_inc(&r->_refcount);
}

static inline int put_replica_testzero(struct replica_struct *r)
{
	return atomic_dec_and_test(&r->_refcount);
}

static inline void put_replica(struct replica_struct *r)
{
	if (put_replica_testzero(r))
		__put_replica_struct(r);
}

/*
 * Reset HEAD to 0.
 * This is safe because we have already set the Flush bit.
 * And others will not be allowed to alloc.
 */
static inline void reset_replica_head(struct replica_struct *r)
{
	r->HEAD = 0;
}

void flush_replica_struct(struct replica_struct *r);

void dump_replica_log(struct replica_log *log, int idx);
void dump_replica_struct(struct replica_struct *r, char *reason);
void dump_all_replica(void);

/* async log flush */
struct log_flush_job {
	struct replica_struct	*r;
	struct list_head	list;
};
void submit_replcia_flush_job(struct log_flush_job *job);
void __init init_memory_flush_thread(void);

/*
 * Primary Memory VMA Replication
 */

#ifdef CONFIG_REPLICATION_VMA
void replicate_vma(struct lego_task_struct *p, int action,
		   unsigned long new_addr, unsigned long new_len,
		   unsigned long old_addr, unsigned long old_len);
#else
static inline void replicate_vma(struct lego_task_struct *p, int action,
		   unsigned long new_addr, unsigned long new_len,
		   unsigned long old_addr, unsigned long old_len)
{ }
#endif

#endif /* _LEGO_MEMORY_REPLICA_H_ */
