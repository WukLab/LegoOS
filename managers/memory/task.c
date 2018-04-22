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

#define PID_ARRAY_HASH_BITS	10

static DEFINE_HASHTABLE(node_pid_hash, PID_ARRAY_HASH_BITS);
static DEFINE_SPINLOCK(hashtable_lock);

static int getKey(unsigned int node, unsigned int pid)
{
        return node*10000+pid*10;
}

int __must_check ht_insert_lego_task(struct lego_task_struct *tsk)
{
	struct lego_task_struct *p;
	unsigned int key;
	unsigned int node, pid;

	BUG_ON(!tsk || !tsk->pid);

	pid = tsk->pid;
	node = tsk->node;
	key = getKey(node, pid);

	spin_lock(&hashtable_lock);
	hash_for_each_possible(node_pid_hash, p, link, key) {
		if (unlikely(p->pid == pid && p->node ==node)) {
			spin_unlock(&hashtable_lock);
			return -EEXIST;
		}
	}
	hash_add(node_pid_hash, &tsk->link, key);
	spin_unlock(&hashtable_lock);

	return 0;
}

struct lego_task_struct *alloc_lego_task_struct(void)
{
	struct lego_task_struct *tsk;

	tsk = kzalloc(sizeof(*tsk), GFP_KERNEL);
	if (tsk) {
		spin_lock_init(&tsk->task_lock);
	}
	return tsk;
}

/*
 * Free @tsk
 * @tsk is not queued into hashtable when called.
 */
void free_lego_task_struct(struct lego_task_struct *tsk)
{
	BUG_ON(hash_hashed(&tsk->link));
	kfree(tsk);
}

void free_lego_task(struct lego_task_struct *tsk)
{
	unsigned int node, pid, key;
	struct lego_task_struct *p;

	BUG_ON(!tsk);
	BUG_ON(!hash_hashed(&tsk->link));

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

	if (unlikely(!pid))
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

void dump_lego_tasks(void)
{
	struct lego_task_struct *p;
	int i;

	spin_lock(&hashtable_lock);
	pr_info("----- Start Dump Tasks\n");
	hash_for_each(node_pid_hash, i, p, link) {
		pr_info("  node:%u comm: %s pid: %u vnode_id: %u parent_pid:%u home_node: %u\n",
			p->node, p->comm, p->pid, p->vnode_id, p->parent_pid, p->home_node);
	}
	pr_info("----- Finish Dump Tasks\n");
	spin_unlock(&hashtable_lock);
}
