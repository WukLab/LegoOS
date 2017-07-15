/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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
#include <lego/comp_common.h>

#include <memory/include/vm.h>
#include <memory/include/pid.h>

#define PID_ARRAY_HASH_BITS	10

static DEFINE_HASHTABLE(node_pid_hash, PID_ARRAY_HASH_BITS);
static DEFINE_SPINLOCK(hashtable_lock);

static int getKey(unsigned int node, unsigned int pid)
{
        return node*10000+pid*10;
}

struct lego_task_struct *
alloc_lego_task(unsigned int node, unsigned int pid)
{
	struct lego_task_struct *tsk, *p;
	unsigned int key;

	if (!node || !pid)
                return ERR_PTR(-EINVAL);

	tsk = kmalloc(sizeof(*tsk), GFP_KERNEL);
	if (!tsk)
		return ERR_PTR(-ENOMEM);
	tsk->node = node;
	tsk->pid = pid;

	key = getKey(node, pid);

	spin_lock(&hashtable_lock);
	hash_for_each_possible(node_pid_hash, p, link, key) {
		if (unlikely(p->pid == pid && p->node ==node)) {
			spin_unlock(&hashtable_lock);
			return ERR_PTR(-EEXIST);
		}
	}
	hash_add(node_pid_hash, &tsk->link, key);  
	spin_unlock(&hashtable_lock);

	return tsk;
}

void free_lego_task(struct lego_task_struct *tsk)
{
	unsigned int node, pid, key;
	struct lego_task_struct *p;

	BUG_ON(!tsk);

	node = tsk->node;
	pid = tsk->pid;
	key = getKey(node, pid);

	spin_lock(&hashtable_lock);
	hash_for_each_possible(node_pid_hash, p, link, key) {
		if (likely(p->node == node && p->pid == pid)) {
			hash_del(&p->link);
			spin_unlock(&hashtable_lock);
			kfree(tsk);
			return;
		}
	}
	spin_unlock(&hashtable_lock);
	WARN(1, "fail to find tsk->(node:%u,pid:%u)\n", node, pid);
}

struct lego_task_struct *
find_lego_task_by_pid(unsigned int node, unsigned int pid)
{
	struct lego_task_struct *tsk;
	unsigned int key;

	if (!node || !pid)
		return NULL;

	key = getKey(node, pid);
	spin_lock(&hashtable_lock);
	hash_for_each_possible(node_pid_hash, tsk, link, key) {
		if (likely(tsk->pid == pid && tsk->node == node)) {
			spin_unlock(&hashtable_lock);
			return tsk;        
		}
        }
        spin_unlock(&hashtable_lock);

	return NULL;
}

/**
 * Similar to copy_process(), init a new lego task struct.
 * and its lego mm struct.
 *
 * TODO: thread group?
 * Reuse some data structures?
 * Accounting relationship with existing threads?
 * May need more info in fork payload!
 */
int init_lego_task(struct lego_task_struct *p)
{
	BUG_ON(!p);

	spin_lock_init(&p->task_lock);

	if (!lego_mm_alloc(p))
		return -ENOMEM;
	return 0;
}
