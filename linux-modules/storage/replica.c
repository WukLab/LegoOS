/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/hashtable.h>

#include "../fit/fit_config.h"
#include "storage.h"
#include "common.h"
#include "replica.h"
#include "stat.h"

static DEFINE_HASHTABLE(replica_ht, REPLICA_HASH_TABLE_SIZE_BIT);
static DEFINE_SPINLOCK(replica_ht_lock);

static inline bool __same_replica(struct replica_log_info *r,
				  unsigned int pid, unsigned int vnode_id)
{
	if (r->pid		== pid &&
	    r->vnode_id		== vnode_id)
		return true;
	return false;
}

static inline bool same_replica(struct replica_log_info *r1,
				struct replica_log_info *r2)
{
	return __same_replica(r1, r2->pid, r2->vnode_id);
}

static int __enqueue_replica_log_info(struct replica_log_info *new)
{
	struct replica_log_info *r;

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

static void close_replica_file(struct replica_log_info *r)
{
	if (!r->filp_replica)
		return;
	filp_close(r->filp_replica, NULL);
}

static void close_mmap_file(struct replica_log_info *r)
{
	if (!r->filp_mmap)
		return;
	filp_close(r->filp_mmap, NULL);
}

unsigned char replica_base_directory[] = "/root/lego-replica-file-";
unsigned char mmap_base_directory[] = "/root/lego-mmap-file-";

static inline void init_replica_f_name(struct replica_log_info *r)
{
	sprintf(r->f_name_replica, "%sv%d-p%d",
		replica_base_directory, r->vnode_id, r->pid);
}

static inline void init_mmap_f_name(struct replica_log_info *r)
{
	sprintf(r->f_name_mmap, "%sv%d-p%d",
		mmap_base_directory, r->vnode_id, r->pid);
}

/*
 * Create replica and mmap log files
 * for a freshly created @r.
 */
static int create_files(struct replica_log_info *r)
{
	struct file *filp;

	init_replica_f_name(r);
	init_mmap_f_name(r);

	filp = filp_open(r->f_name_replica, O_LARGEFILE | O_CREAT, 0644);
	if (IS_ERR(filp))
		return PTR_ERR(filp);
	r->filp_replica = filp;

	filp = filp_open(r->f_name_mmap, O_LARGEFILE | O_CREAT, 0644);
	if (IS_ERR(filp)) {
		close_replica_file(r);
		return PTR_ERR(filp);
	}
	r->filp_mmap = filp;

	return 0;
}

void __put_replica_log_info(struct replica_log_info *r)
{
	close_mmap_file(r);
	close_replica_file(r);
	kfree(r);
}

static struct replica_log_info *alloc_replica_log_info(void)
{
	struct replica_log_info *r;

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return NULL;

	atomic_set(&r->_refcount, 1);
	spin_lock_init(&r->lock);
	return r;
}

static struct replica_log_info *
find_or_alloc_replica_log_info(unsigned int pid, unsigned int vnode_id)
{
	struct replica_log_info *r;
	unsigned int hash_key;
	int ret;

	hash_key = replica_get_hash_key(pid, vnode_id);

	spin_lock(&replica_ht_lock);
	hash_for_each_possible(replica_ht, r, hlist, hash_key) {
		if (likely(__same_replica(r, pid, vnode_id)))
			goto unlock;
	}

	/* First time, allocate one */
	r = alloc_replica_log_info();
	if (!r)
		goto unlock;
	r->pid = pid;
	r->vnode_id = vnode_id;
	r->hash_key = hash_key;

	ret = create_files(r);
	if (ret) {
		put_replica_log_info(r);
		r = NULL;
		goto unlock;
	}

	/* Enqueue hashtable */
	ret = __enqueue_replica_log_info(r);
	if (ret) {
		put_replica_log_info(r);
		r = NULL;
	}

unlock:
	spin_unlock(&replica_ht_lock);
	return r;
}

static int append_replica(struct replica_log_info *r,
			  struct replica_log *log_array, int nr_log)
{
	struct file *f;
	size_t count;
	ssize_t written;

	f = r->filp_replica;
	count = nr_log * (sizeof(*log_array));

	written = local_file_write(f, (char *)log_array, count, &r->HEAD_REPLICA);
	if (written != count)
		return -EFAULT;
	return 0;
}

static inline int append_mmap(struct replica_log_info *r,
			      struct replica_vma_log *log)
{
	struct file *f;
	size_t count;
	ssize_t written;

	f = r->filp_mmap;
	count = sizeof(*log);

	written = local_file_write(f, (char *)log, count, &r->HEAD_MMAP);
	if (written != count)
		return -EFAULT;
	return 0;
}

#if 0
#define dp(fmt, ...)		\
	pr_crit("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
#define dp(fmt, ...) do { } while (0)
#endif

/*
 * Handle memory replication flush from Secondary Memory
 */
void handle_replica_flush(void *_msg, u64 desc)
{
	struct m2s_replica_flush_msg *msg = _msg;
	struct replica_log_info *r;
	struct replica_log *log_array;
	unsigned int nr_log;
	unsigned int pid, vnode_id;
	int reply;

	nr_log = msg->nr_log;
	log_array = (struct replica_log *)(&msg->log);

	pid = log_array->meta.pid;
	vnode_id = log_array->meta.vnode_id;

	r = find_or_alloc_replica_log_info(pid, vnode_id);
	if (!r) {
		reply = -ENOMEM;
		goto out;
	}

	reply = append_replica(r, log_array, nr_log);
out:
	ibapi_reply_message(&reply, sizeof(reply), desc);
}

/*
 * Handle VMA replication from Primary Memory
 */
void handle_replica_vma(void *_msg, u64 desc)
{
	struct m2s_replica_vma_msg *msg = _msg;
	struct replica_vma_log *log = &msg->log;
	struct replica_log_info *r;
	int reply = 0;

	dp("pid: %d vnode_id: %d action: %d [%#lx-%#lx], [%#lx-%#lx]\n",
		log->pid, log->vnode_id, log->action,
		log->new_addr, log->new_addr + log->new_len,
		log->old_addr, log->old_addr + log->old_len);

	r = find_or_alloc_replica_log_info(log->pid, log->vnode_id);
	if (!r) {
		reply = -ENOMEM;
		goto out;
	}

	reply = append_mmap(r, log);
out:
	ibapi_reply_message(&reply, sizeof(reply), desc);
}
