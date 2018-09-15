/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <processor/processor.h>

#ifdef CONFIG_DEBUG_FORK
#define fork_debug(fmt, ...)						\
	pr_debug("%s(cpu%d): " fmt "\n", __func__, smp_processor_id(),	\
		__VA_ARGS__)

static void fork_reply_dump(struct fork_reply_struct *reply)
{
	int i;
	struct fork_vmainfo *info = reply->vmainfos;

	fork_debug("Total VMAs: %d", reply->vma_count);
	for (i = 0; i < reply->vma_count; i++)
		fork_debug("[vma %d] %lx-%lx, flags: %lx", i,
			   info[i].vm_start, info[i].vm_end, info[i].vm_flags);
}
#else
static inline void fork_debug(const char *fmt, ...) { }
static inline void fork_reply_dump(struct fork_reply_struct *reply) { }
#endif

/*
 * Return 0 on success, -ENOMEM on failure.
 * fork() syscall does not have too many errno options.
 *
 * We return the reply struct which contains the vma info array.
 * The caller is responsible to do the free.
 */
void *p2m_fork(struct task_struct *p, unsigned long clone_flags)
{
	struct p2m_fork_struct payload;
	struct fork_reply_struct *reply;
	int retlen;

	BUG_ON(!p);

	reply = kmalloc(sizeof(struct fork_reply_struct), GFP_KERNEL);
	if (!reply)
		return ERR_PTR(-ENOMEM);

	payload.pid = p->pid;
	payload.tgid = p->tgid;
	payload.parent_tgid = p->real_parent->tgid;
	payload.clone_flags = clone_flags;
	memcpy(payload.comm, p->comm, TASK_COMM_LEN);

	retlen = net_send_reply_timeout(get_memory_home_node(p), P2M_FORK, &payload,
				sizeof(payload), reply, sizeof(*reply), false,
				DEF_NET_TIMEOUT);

	/*
	 * If there is a non-zero return, the reply
	 * message might be only four bytes.
	 */
	if (reply->ret) {
		pr_warn("%s():. ret %d:%s cur:%d-%s new:%d\n",
			FUNC, reply->ret, perror(reply->ret),
			current->pid, current->comm, p->pid);
		return ERR_PTR(reply->ret);
	}

	fork_reply_dump(reply);
	return reply;
}

static inline int choose_home_mnode_no_parent(struct task_struct *p)
{
	return DEF_MEM_HOMENODE;
}

static inline int choose_replica_mnode_no_parent(struct task_struct *p)
{
	if (get_memory_home_node(p) != UNSET_HOME_NODE)
		return get_memory_home_node(p);
	return DEF_MEM_HOMENODE;
}

static inline int choose_replica_mnode(struct task_struct *new,
				       struct task_struct *parent)
{
	if (get_replica_node(parent) != UNSET_REPLICA_NODE)
		return get_replica_node(parent);

	if (get_memory_home_node(new) != UNSET_HOME_NODE)
		return get_memory_home_node(new);

	return DEF_MEM_HOMENODE;
}

/*
 * Called during fork() before setting the new mm
 * We should initialize all the node ids.
 *
 * NOTE:
 * This is called before @new's pid was setup.
 * So, at this stage, new->pid==parent->pid.
 */
void fork_processor_data(struct task_struct *new, struct task_struct *parent,
			 unsigned long clone_flags)
{
	int nid;

	if (clone_flags & CLONE_GLOBAL_THREAD) {
		/*
		 * Creating a new user process, two cases:
		 * - parent is kernel thread, no context in remote memory
		 * - parent is user thread, has context in remote memory
		 */
		if (get_memory_home_node(parent) == UNSET_HOME_NODE) {
			/*
			 * case 1: this new process does not have any
			 * parent context in any remote memory components.
			 *
			 * So we have the freedom to choose any memory as its
			 * home node at this point.
			 */
			nid = choose_home_mnode_no_parent(new);
			set_memory_home_node(new, nid);

			nid = choose_replica_mnode_no_parent(new);
			set_replica_node(new, nid);
		} else {
			/*
			 * case 2: We do have a parent that has user context
			 * in remote memory. We have no choice but to re-use
			 * the home node of its parent. However, we do have
			 * the freedom to choose a new replica node.
			 */
			nid = get_memory_home_node(parent);
			set_memory_home_node(new, nid);

			nid = choose_replica_mnode(new, parent);
			set_replica_node(new, nid);
		}
	} else {
		/*
		 * Otherwise, two extra cases:
		 * - new user thread within a user process
		 * - new kernel thread
		 *
		 * Both of them can copy the data from parent
		 */
		nid = get_memory_home_node(parent);
		set_memory_home_node(new, nid);

		nid = get_replica_node(parent);
		set_replica_node(new, nid);

		nid = get_pgcache_home_node(parent);
		set_pgcache_home_node(new, nid);

		nid = get_storage_home_node(parent);
		set_storage_home_node(new, nid);
	}
}
