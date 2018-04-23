/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_LINUX_STORAGE_REPLICA_H_
#define _LEGO_LINUX_STORAGE_REPLICA_H_

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

#define	REPLICA_LOG_MAX_FILENAME	128

struct replica_log_info {
	unsigned int		pid;
	unsigned int		vnode_id;
	unsigned int		hash_key;

	loff_t			HEAD_REPLICA;
	loff_t			HEAD_MMAP;
	unsigned char		f_name_replica[REPLICA_LOG_MAX_FILENAME];
	unsigned char		f_name_mmap[REPLICA_LOG_MAX_FILENAME];
	struct file		*filp_replica;
	struct file		*filp_mmap;

	atomic_t		_refcount;
	spinlock_t		lock;

	struct hlist_node	hlist;
};

static inline void get_replica_log_info(struct replica_log_info *r)
{
	atomic_inc(&r->_refcount);
}

static inline int put_replica_log_info_testzero(struct replica_log_info *r)
{
	return atomic_dec_and_test(&r->_refcount);
}

void __put_replica_log_info(struct replica_log_info *r);

static inline void put_replica_log_info(struct replica_log_info *r)
{
	if (put_replica_log_info_testzero(r))
		__put_replica_log_info(r);
}

#endif /* _LEGO_LINUX_STORAGE_REPLICA_H_ */
