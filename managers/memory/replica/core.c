/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/slab.h>
#include <lego/kernel.h>
#include <lego/spinlock.h>
#include <lego/checksum.h>
#include <lego/hashtable.h>
#include <lego/fit_ibapi.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/task.h>
#include <memory/replica.h>
#include <processor/pcache.h>

#ifdef CONFIG_DEBUG_HANDLE_REPLICA
# define replica_debug(fmt, ...)	\
	pr_debug("%s() CPU%d " fmt "\n", __func__, smp_processor_id(), __VA_ARGS__)
#else
# define replica_debug(fmt, ...)	do { } while (0)
#endif

/*
 * This hashtable maps pid, vnode_id, nid_processor, nid_memory
 * to a unique replica_struct, which contains the per-process
 * replication log and extra metadata.
 */
static DEFINE_HASHTABLE(replica_ht, REPLICA_HASH_TABLE_SIZE_BIT);
static DEFINE_SPINLOCK(replica_ht_lock);

/*
 * All IDs need to match
 */
static inline bool
__same_replica(struct replica_struct *r, unsigned int pid, unsigned int vnode_id)
{
	if (r->pid		== pid	&&
	    r->vnode_id		== vnode_id)
		return true;
	return false;
}

static inline bool same_replica(struct replica_struct *r1,
				struct replica_struct *r2)
{
	return __same_replica(r1, r2->pid, r2->vnode_id);
}

/*
 * Enter with @replica_ht_lock held
 */
static int __enqueue_replica_struct(struct replica_struct *new)
{
	struct replica_struct *r;

	if (!new->hash_key) {
		WARN_ON_ONCE(1);
		return -EINVAL;
	}

	hash_for_each_possible(replica_ht, r, hlist, new->hash_key) {
		if (unlikely(same_replica(r, new)))
			return -EEXIST;
	}
	hash_add(replica_ht, &new->hlist, new->hash_key);

	return 0;
}

int dequeue_replica_struct(struct replica_struct *ice)
{
	struct replica_struct *r;

	spin_lock(&replica_ht_lock);
	hash_for_each_possible(replica_ht, r, hlist, ice->hash_key) {
		if (likely(same_replica(r, ice))) {
			hash_del(&ice->hlist);
			spin_unlock(&replica_ht_lock);
			return 0;
		}
	}
	spin_unlock(&replica_ht_lock);

	WARN_ON_ONCE(1);
	return -ENOMEM;
}

/*
 * This determines how many log entries
 * are allocated for
 */
unsigned int mem_sysctl_nr_log = 8;

static inline void init_replica_struct(struct replica_struct *r)
{
	r->pid = 0;
	r->vnode_id = 0;
	r->nid_processor = 0;
	r->nid_memory = 0;
	r->hash_key = 0;
	r->flags = 0;

	r->nr_log = 0;
	r->log = NULL;
	r->HEAD = 0;
	spin_lock_init(&r->lock);

	init_replica_refcount(r);

	atomic_set(&r->nr_batch_flush, 0);
	atomic_set(&r->nr_created, 0);
}

/*
 * Allocate log buffer and initialize replica_struct.
 */
static struct replica_struct *alloc_replica_struct(void)
{
	struct replica_struct *replica;
	struct replica_log *log;
	unsigned int nr_log;

	replica = kmalloc(sizeof(*replica), GFP_KERNEL);
	if (!replica)
		return NULL;
	init_replica_struct(replica);

	/* cache locally in case it changed */
	nr_log = mem_sysctl_nr_log;
	log = kzalloc(nr_log * sizeof(*log), GFP_KERNEL);
	if (!log) {
		kfree(replica);
		return NULL;
	}

	replica->nr_log = nr_log;
	replica->log = log;
	return replica;
}

/* Called when _refcount of @r drops to 0 */
void __put_replica_struct(struct replica_struct *r)
{
	BUG_ON(!r->log);
	kfree(r->log);
	kfree(r);
}

static struct replica_struct *
find_or_alloc_replica_struct(unsigned int pid, unsigned int vnode_id,
			     unsigned int nid_processor, unsigned int nid_memory)
{
	struct replica_struct *r;
	unsigned int hash_key;
	int ret;

	hash_key = replica_get_hash_key(pid, vnode_id);

	spin_lock(&replica_ht_lock);
	hash_for_each_possible(replica_ht, r, hlist, hash_key) {
		if (likely(__same_replica(r, pid, vnode_id)))
			goto unlock;
	}

	/* First time, allocate one */
	r = alloc_replica_struct();
	if (!r)
		goto unlock;

	r->pid = pid;
	r->vnode_id = vnode_id;
	r->nid_processor = nid_processor;
	r->nid_memory = nid_memory;
	r->hash_key = hash_key;

	ret = __enqueue_replica_struct(r);
	if (ret) {
		dump_replica_struct(r);
		put_replica(r);
		r = NULL;
	}

unlock:
	spin_unlock(&replica_ht_lock);
	return r;
}

static inline void wait_for_replica_log(struct replica_log *log, int idx)
{
	unsigned long wait_start = jiffies;

	while (unlikely(!ReplicaLogValid(log))) {
		cpu_relax();

		/* Break out after 10 seconds */
		if (unlikely(time_after(jiffies, wait_start + 10 * HZ))) {
			dump_replica_log(log, idx);
			panic("We should have it valid shortly, but?");
		}
	}
}

/*
 * Wait until all replica_log become valid
 * Called with @r locked
 */
static inline void wait_for_replica_struct(struct replica_struct *r)
{
	int i;
	struct replica_log *log;

	/* Must be called with log full state */
	BUG_ON(r->HEAD != r->nr_log);

	for (i = 0; i < r->nr_log; i++) {
		log = &r->log[i];
		wait_for_replica_log(log, i);
	}
}

static inline struct replica_log * __alloc_replica_log(struct replica_struct *r)
{
	struct replica_log *log;

	log = &r->log[r->HEAD];
	r->HEAD++;

	return log;
}

/*
 * Quick check if @r's log is full.
 * Called with @r locked
 */
static inline bool replica_log_full(struct replica_struct *r)
{
	if (unlikely(r->HEAD == r->nr_log))
		return true;
	return false;
}

/*
 * Reset HEAD to 0.
 * Called with @r locked
 */
static inline void reset_replica_head(struct replica_struct *r)
{
	r->HEAD = 0;
}

unsigned long mem_sysctl_replica_alloc_timeout_sec = 30;

struct replica_log *alloc_replica_log(struct replica_struct *r)
{
	struct replica_log *log;
	unsigned long start = jiffies;

	spin_lock(&r->lock);
retry:
	if (unlikely(replica_log_full(r))) {
		if (time_after(jiffies, start + mem_sysctl_replica_alloc_timeout_sec * HZ)) {
			spin_unlock(&r->lock);
			dump_replica_struct(r);
			WARN_ON_ONCE(1);
			return NULL;
		}

		/*
		 * - Wait until all logs are valid
		 * - Flush whole log back to storage
		 * - Reset HEAD to 0
		 */
		wait_for_replica_struct(r);
		flush_replica_struct(r);
		reset_replica_head(r);
		goto retry;
	}
	log = __alloc_replica_log(r);
	spin_unlock(&r->lock);

	return log;
}

static inline int append_replica_log(struct replica_struct *r,
				     struct replica_log *src_log)
{
	struct replica_log *dst_log;

	dst_log = alloc_replica_log(r);
	if (unlikely(!dst_log))
		return -ENOMEM;

	memcpy(dst_log, src_log, sizeof(*dst_log));
	SetReplicaLogValid(dst_log);
	/* also a implicit smp_wmb */

	return 0;
}

void handle_p2m_replica(void *_msg, u64 desc)
{
	struct p2m_replica_msg *msg;
	struct replica_log *src_log;
	struct replica_log_meta *src_meta;
	struct replica_struct *replica;
	unsigned int pid, vnode_id, nid_processor, nid_memory;
	int reply = 0;

	msg = _msg;
	src_log = &msg->log;
	src_meta = &src_log->meta;

	pid = src_meta->pid;
	vnode_id = src_meta->vnode_id;
	nid_memory = src_meta->nid_memory;
	nid_processor = src_meta->nid_processor;

	replica = find_or_alloc_replica_struct(pid, vnode_id, nid_processor, nid_memory);
	if (!replica) {
		reply = -ENOMEM;
		goto out;
	}

	reply = append_replica_log(replica, src_log);
	dump_replica_struct(replica);
out:
	ibapi_reply_message(&reply, sizeof(reply), desc);
}
