/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/rbtree.h>
#include <lego/slab.h>
#include <lego/fit_ibapi.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/task.h>
#include <memory/file_types.h>
#include <memory/distvm.h>
#include <memory/thread_pool.h>

#ifdef CONFIG_DEBUG_HANDLE_FORK
#define fork_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)

#define dump_both_vmas(mm, oldmm)		\
	do {					\
		dump_all_vmas_simple(mm);	\
		dump_all_vmas_simple(oldmm);	\
	} while (0)

static void DUMP(struct lego_mm_struct *mm)
{
	dump_all_vmas_simple(mm);
	dump_all_vmas(mm);
	dump_lego_mm(mm);
}

static void debug_fork_dump_mm(struct lego_mm_struct *new_mm,
			       struct lego_task_struct *child,
			       struct lego_task_struct *parent)
{
	pr_debug("**** Dump Child (%d) mm:\n", child->pid);
	DUMP(new_mm);
	pr_debug("**** Finish Dump Child (%d) mm\n", child->pid);

	if (parent) {
		pr_debug("**** Dump Parent (%d) mm:\n", parent->pid);
		DUMP(parent->mm);
		pr_debug("**** Finish Dump Parent (%d) mm:\n", parent->pid);
	} else
		pr_debug("**** No Parent, above is brand new mm\n");
}
#else
static inline void fork_debug(const char *fmt, ...) { }
#define dump_both_vmas(mm, oldmm)	do { } while (0)
#define debug_fork_dump_mm(foo, bar, a)	do { } while(0)
#endif

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
static void insert_freepool(struct lego_mm_struct *mm, struct vm_pool_struct *new)
{
	struct rb_root *rbroot = &mm->vmpool_rb;
	struct rb_node **rb_link = &rbroot->rb_node, *rb_parent = NULL;

	while (*rb_link) {
		struct vm_pool_struct *pool;
		pool = rb_entry(*rb_link, struct vm_pool_struct, vmr_rb);

		rb_parent = *rb_link;
		if (pool->pool_start >= new->pool_end)
			rb_link = &((*rb_link)->rb_left);
		else if (pool->pool_end <= new->pool_start)
			rb_link = &((*rb_link)->rb_right);
		else
			BUG();
	}

	rb_link_node(&new->vmr_rb, rb_parent, rb_link);
	rb_insert_color(&new->vmr_rb, rbroot);
}

static int dup_lego_mmap_freepool(struct lego_mm_struct *mm,
				  struct lego_mm_struct *oldmm)
{
	struct vm_pool_struct *pos, *n;

	mm->vmpool_rb = RB_ROOT;
	rbtree_postorder_for_each_entry_safe(pos, n, &oldmm->vmpool_rb, vmr_rb) {
		struct vm_pool_struct *new;

		new = kmalloc(sizeof(struct vm_pool_struct), GFP_KERNEL);
		if (!new)
			return -ENOMEM;

		new->pool_start = pos->pool_start;
		new->pool_end = pos->pool_end;
		insert_freepool(mm, new);
	}

	return 0;
}

static int dup_lego_mmap_single_vmatree(struct lego_mm_struct *mm,
					struct lego_mm_struct *oldmm,
					struct vma_tree *oldroot)
{
	int ret = 0;
	struct vm_area_struct *mpnt, *tmp, *prev, **pprev;
	struct rb_node **rb_link, *rb_parent;
	struct vma_tree *newroot;

	/* create new root on new mm */
	newroot = kmalloc(sizeof(struct vma_tree), GFP_KERNEL);
	if (!newroot)
		return -ENOMEM;

	newroot->begin = oldroot->begin;
	newroot->end = oldroot->end;
	newroot->flag = oldroot->flag;
	newroot->max_gap = oldroot->max_gap;
	newroot->mnode = oldroot->mnode;
	INIT_LIST_HEAD(&newroot->list);
	set_vmrange_map(mm, newroot->begin, newroot->end - newroot->begin, newroot);

	rb_link = &mm->mm_rb.rb_node;
	rb_parent = NULL;
	pprev = &mm->mmap;

	prev = NULL;
	for (mpnt = oldroot->mmap; mpnt; mpnt = mpnt->vm_next) {
		struct lego_file *file;

		tmp = kmalloc(sizeof(*tmp), GFP_KERNEL);
		if (!tmp)
			return -ENOMEM;

		*tmp = *mpnt;
		tmp->vm_mm = mm;

		tmp->vm_flags &=
			~(VM_LOCKED|VM_LOCKONFAULT|VM_UFFD_MISSING|VM_UFFD_WP);
		tmp->vm_next = tmp->vm_prev = NULL;

		file = tmp->vm_file;
		if (file) {
			/* Hold 1 more ref is enough now */
			get_lego_file(file);
		}

		/*
		 * Link in the new vma and copy the page table entries.
		 */
		*pprev = tmp;
		pprev = &tmp->vm_next;
		tmp->vm_prev = prev;
		prev = tmp;

		__vma_link_rb(mm, tmp, rb_link, rb_parent);
		rb_link = &tmp->vm_rb.rb_right;
		rb_parent = &tmp->vm_rb;

		mm->map_count++;
		ret = lego_copy_page_range(mm, oldmm, mpnt);

		/*
		 * Callback to underlying fs hook if exists:
		 */
		if (tmp->vm_ops && tmp->vm_ops->open)
			tmp->vm_ops->open(tmp);

		if (ret)
			return ret;

	}
	/* update new vma tree root */
	save_update_vma_context(mm, newroot);

	return ret;
}

static int dup_lego_mmap_local_vmatree(struct lego_mm_struct *mm,
				       struct lego_mm_struct *oldmm)
{
	int i = 0;

	while (i < VMR_COUNT) {
		int ret = 0;
		struct vma_tree *root = oldmm->vmrange_map[i];
		if (!root) {
			i++;
			continue;
		}

		if (!is_local(root->mnode)) {
			VMA_BUG_ON(!is_homenode(oldmm->task));
			i = vmr_idx(root->end);
			continue;
		}

		i = vmr_idx(VMR_ALIGN(root->end));
		ret = dup_lego_mmap_single_vmatree(mm, oldmm, root);
		if (ret)
			return ret;

		if (is_homenode(oldmm->task))
			sort_node_gaps(mm, mm->vmrange_map[vmr_idx(root->begin)]);
	}
	return 0;
}

/*
 * We send the fork() requests to all non-homenode memory nodes.
 * All of them will reply the number of VMAs they have, and we
 * collect them into one big array.
 */
static int distribute_m2m_fork(struct lego_task_struct *parent,
			       struct lego_task_struct *child, u64 mnode,
			       struct fork_reply_struct *p2m_reply)
{
	int ret_len, ret, old_vma_count;
	struct m2m_fork_struct info;
	struct fork_reply_struct *m2m_reply;

	m2m_reply = kmalloc(sizeof(struct fork_reply_struct), GFP_KERNEL);
	if (!m2m_reply)
		return -ENOMEM;

	info.parent_pid = parent->pid;
	info.child_pid = child->pid;
	info.prcsr_nid = child->node;

	ret_len = net_send_reply_timeout(mnode, M2M_FORK, &info,
			sizeof(struct m2m_mmap_struct), m2m_reply,
			sizeof(struct fork_reply_struct),
			false, FIT_MAX_TIMEOUT_SEC);
	if (ret_len == sizeof(int)) {
		ret = m2m_reply->ret;
		kfree(m2m_reply);
		return ret;
	}

	/*
	 * Copy the info from non-home node to the reply
	 * buffer, that is going to be sent to P.
	 * This code is executed one by one, no need to lock.
	 */
	old_vma_count = p2m_reply->vma_count;
	p2m_reply->vma_count += m2m_reply->vma_count;
	BUG_ON(p2m_reply->vma_count >= DEFAULT_MAX_MAP_COUNT);

	memcpy(&p2m_reply->vmainfos[old_vma_count], m2m_reply->vmainfos,
		m2m_reply->vma_count * sizeof(struct fork_vmainfo));

	kfree(m2m_reply);
	return 0;
}

static void get_vmas_onetree(struct vma_tree *root, struct fork_reply_struct *reply)
{
	struct vm_area_struct *pos;

	VMA_WARN(!root, "vma tree root given is an empty pointer\n");

	pos = root->mmap;
	if (!pos) {
		vma_debug("No vmas in this tree\n");
		return;
	}

	for (; pos; pos = pos->vm_next) {
		WARN_ON_ONCE(reply->vma_count >= DEFAULT_MAX_MAP_COUNT);

		reply->vmainfos[reply->vma_count].vm_start = pos->vm_start;
		reply->vmainfos[reply->vma_count].vm_end = pos->vm_end;
		reply->vmainfos[reply->vma_count].vm_flags = pos->vm_flags;
		fork_debug("vma_count: %d, %lx-%lx, vm_flags: %lx",
			  reply->vma_count, pos->vm_start, pos->vm_end, pos->vm_flags);

		reply->vma_count++;
	}
}

static void get_vmas_onenode(struct lego_mm_struct *mm, struct fork_reply_struct *reply)
{
	struct vma_tree **map = mm->vmrange_map;
	int idx = 0;

	for (idx = 0; idx < VMR_COUNT; idx++) {
		struct vma_tree *root = map[idx];
		if (!root)
			continue;

		/* homenode root may be for other M, no vma info under these roots */
		BUG_ON(!is_homenode(mm->task) && !is_local(root->mnode));
		if (!is_local(root->mnode))
			continue;

		fork_debug("parent pid: %d",mm->task->pid);
		get_vmas_onetree(root, reply);
		idx = vmr_idx(VMR_ALIGN(root->end)) - 1;
	}
}

/*
 * We have three different entry points to create a new task
 * - p2m fork
 * - m2m fork
 * - m2m mmap
 *
 * HACK!!! Check all the necessary setup steps.
 */
void handle_m2m_fork(struct m2m_fork_struct *payload,
		     struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	u32 parent_pid = payload->parent_pid;
	u32 child_pid = payload->child_pid;
	u32 prcsr_nid = payload->prcsr_nid;
	u32 reply_size;
	struct lego_task_struct *parent;
	struct lego_task_struct *child;
	struct fork_reply_struct *reply;

	vma_debug("%s, nid: %d, parent_pid: %d, child_pid: %d, prcsr_nid: %d",
		   __func__, nid, parent_pid, child_pid, prcsr_nid);

	reply = thpool_buffer_tx(tb);
	memset(reply, 0, sizeof(*reply));
	tb_set_tx_size(tb, sizeof(int));

	parent = find_lego_task_by_pid(prcsr_nid, parent_pid);
	if (unlikely(!parent)) {
		reply->ret = -ESRCH;
		return;
	}

	child = alloc_lego_task_struct();
	if (unlikely(!child)) {
		reply->ret = -ENOMEM;
		return;
	}

	child->pid = child_pid;
	child->node = prcsr_nid;
	child->parent_pid = parent_pid;
	mem_set_memory_home_node(child, nid);

	child->mm = lego_mm_alloc(child, NULL);
	if (!child->mm) {
		reply->ret = -ENOMEM;
		free_lego_task_struct(child);
		return;
	}
	/* virtual memory map layout */
	arch_pick_mmap_layout(child->mm);

	/* initialize buffer and copy parent vma information to processor */
	reply->vma_count = 0;
	get_vmas_onenode(parent->mm, reply);

	/* All done, insert into hashtable */
	reply->ret = ht_insert_lego_task(child);
	if (reply->ret) {
		lego_mmput(child->mm);
		free_lego_task_struct(child);

		/* Same process? */
		if (likely(reply->ret == -EEXIST))
			reply->ret = 0;
		return;
	}

	if (down_write_killable(&parent->mm->mmap_sem)) {
		reply->ret = -EINTR;
		return;
	}

	down_write(&child->mm->mmap_sem);

	/* task struct is prepared, start duplication */
	reply->ret = dup_lego_mmap_local_vmatree(child->mm, parent->mm);
	WARN_ON(reply->ret);

	up_write(&child->mm->mmap_sem);
	up_write(&parent->mm->mmap_sem);

	/* everything is fine, update datasize needs to be sent to homenode */
	reply_size = sizeof(int) + sizeof(u32) +
		     reply->vma_count * sizeof(struct fork_vmainfo);
	tb_set_tx_size(tb, reply_size);
}

/*
 * @mm belongs to the new children
 * @oldmm belongs to parent. Must not be NULL.
 */
static int dup_lego_mmap(struct lego_mm_struct *mm,
			 struct lego_mm_struct *oldmm,
			 struct fork_reply_struct *reply)
{
	int ret = 0;
	u64 mnode = 0;

	if (down_write_killable(&oldmm->mmap_sem))
		return -EINTR;

	down_write(&mm->mmap_sem);

	mm->total_vm = oldmm->total_vm;
	mm->data_vm = oldmm->data_vm;
	mm->exec_vm = oldmm->exec_vm;
	mm->stack_vm = oldmm->stack_vm;

	ret = distvm_init_homenode(mm, true);
	if (ret)
		goto out;

	ret = dup_lego_mmap_freepool(mm, oldmm);
	if (ret)
		goto out;

	/* initialize reply vma count to 0 */
	reply->vma_count = 0;
	for (mnode = 0; mnode < NODE_COUNT; mnode++) {
		struct distvm_node *node = oldmm->node_map[mnode];
		struct distvm_node **newnode = &mm->node_map[mnode];

		if (!node)
			continue;

		/* homenode copys everything */
		*newnode = kzalloc(sizeof(struct distvm_node), GFP_KERNEL);
		if (*newnode == NULL) {
			WARN_ON(1);
			ret = -ENOMEM;
			goto out;
		}

		INIT_LIST_HEAD(&((*newnode)->list));
		dup_lego_mmap_local_vmatree(mm, oldmm);

		if (!is_local(mnode)) {
			/* Send request to other nodes */
			ret = distribute_m2m_fork(oldmm->task, mm->task, mnode, reply);
			if (ret)
				goto out;
		} else {
			/* Copy local vma info to reply buffer */
			get_vmas_onenode(oldmm, reply);
		}
	}

out:
	up_write(&mm->mmap_sem);
	up_write(&oldmm->mmap_sem);

	return ret;
}

#else
/*
 * Non-distributed VMA fork() version.
 * This is the most basic one, and is similar to what Linux
 * will do in one single machine.
 */
static int dup_lego_mmap(struct lego_mm_struct *mm,
			 struct lego_mm_struct *oldmm,
			 struct fork_reply_struct *reply)
{
	struct vm_area_struct *mpnt, *tmp, *prev, **pprev;
	struct rb_node **rb_link, *rb_parent;
	int ret = 0;

	if (down_write_killable(&oldmm->mmap_sem))
		return -EINTR;

	down_write(&mm->mmap_sem);

	mm->total_vm = oldmm->total_vm;
	mm->data_vm = oldmm->data_vm;
	mm->exec_vm = oldmm->exec_vm;
	mm->stack_vm = oldmm->stack_vm;

	rb_link = &mm->mm_rb.rb_node;
	rb_parent = NULL;
	pprev = &mm->mmap;

	prev = NULL;
	reply->vma_count = 0;
	for (mpnt = oldmm->mmap; mpnt; mpnt = mpnt->vm_next) {
		struct lego_file *file;
		struct fork_vmainfo *vmainfo;

		tmp = kmalloc(sizeof(*tmp), GFP_KERNEL);
		if (!tmp) {
			ret = -ENOMEM;
			goto out;
		}

		*tmp = *mpnt;
		tmp->vm_mm = mm;

		tmp->vm_flags &=
			~(VM_LOCKED|VM_LOCKONFAULT|VM_UFFD_MISSING|VM_UFFD_WP);
		tmp->vm_next = tmp->vm_prev = NULL;

		file = tmp->vm_file;
		if (file) {
			/* Hold 1 more ref is enough now */
			get_lego_file(file);
		}

		/*
		 * Link in the new vma and copy the page table entries.
		 */
		*pprev = tmp;
		pprev = &tmp->vm_next;
		tmp->vm_prev = prev;
		prev = tmp;

		__vma_link_rb(mm, tmp, rb_link, rb_parent);
		rb_link = &tmp->vm_rb.rb_right;
		rb_parent = &tmp->vm_rb;

		mm->map_count++;
		ret = lego_copy_page_range(mm, oldmm, mpnt);

		/*
		 * Callback to underlying fs hook if exists:
		 */
		if (tmp->vm_ops && tmp->vm_ops->open)
			tmp->vm_ops->open(tmp);

		if (ret)
			goto out;

		/* Fill the reply buffer */
		vmainfo = &reply->vmainfos[reply->vma_count];
		vmainfo->vm_start = mpnt->vm_start;
		vmainfo->vm_end = mpnt->vm_end;
		vmainfo->vm_flags = mpnt->vm_flags;
		reply->vma_count++;
	}

	ret = 0;
out:
	up_write(&mm->mmap_sem);
	up_write(&oldmm->mmap_sem);
	return ret;
}
#endif /* CONFIG_DISTRIBUTED_VMA_MEMORY */

/*
 * This function duplicate mmap layout from parent,
 * which is the basic COW guarantee of fork().
 *
 * The whole lego_mm_struct will be replcaed by a new one
 * when execve() is called. This is also what execve() guarantees.
 * Check managers/memory/loader/vm.c for detail.
 */
static int dup_lego_mm(struct lego_task_struct *t,
		       struct lego_task_struct *parent,
		       struct fork_reply_struct *reply)
{
	struct lego_mm_struct *mm, *oldmm;
	int err;

	mm = lego_mm_alloc(t, parent);
	if (!mm)
		return -ENOMEM;
	t->mm = mm;

	if (parent) {
		oldmm = parent->mm;
		err = dup_lego_mmap(mm, oldmm, reply);
		if (err)
			goto out;
	} else {
		/*
		 * The only possibility that parent is NULL
		 * is that this is the first process here.
		 * And it will call the execve() immediately.
		 */
	}
	debug_fork_dump_mm(mm, t, parent);

	return 0;

out:
	lego_mmput(mm);
	return err;
}

/*
 * The flow of this function:
 * 1) allocate task struct, duplicate VMA info
 * 2) If distributed-VMA is on, and we have active non-home memory node,
 *    then send requests (m2m_fork) to others.
 * 3) Reply the VMA info array back to P. P will use this to play with pgtable.
 */
void handle_p2m_fork(struct p2m_fork_struct *payload,
		     struct common_header *hdr, struct thpool_buffer *tb)
{
	unsigned int nid = hdr->src_nid;
	unsigned int tgid = payload->tgid;
	unsigned int parent_tgid = payload->parent_tgid;
	unsigned int reply_size;
	struct lego_task_struct *tsk, *parent;
	struct fork_reply_struct *reply;

	fork_debug("nid:%u,pid:%u,tgid:%u,parent_tgid:%u",
		nid, payload->pid, tgid, parent_tgid);

	reply = thpool_buffer_tx(tb);
	memset(reply, 0, sizeof(*reply));
	tb_set_tx_size(tb, sizeof(int));

	parent = find_lego_task_by_pid(nid, parent_tgid);
	if (!parent && parent_tgid != 1)
		WARN_ONCE(1, "From processor-daemon?");

	tsk = alloc_lego_task_struct();
	if (!tsk) {
		reply->ret = -ENOMEM;
		return;
	}

	/*
	 * All threads within process share one VM
	 * So we actually use tgid (thread-group-id) to create
	 * a lego-tsk entity.
	 *
	 * All following requests sent from processor must use tgid.
	 */

	tsk->pid = tgid;
	tsk->parent_pid = parent_tgid;
	tsk->node = nid;
	mem_set_memory_home_node(tsk, LEGO_LOCAL_NID);
	lego_set_task_comm(tsk, payload->comm);

	/* Duplicate the mmap from parent */
	reply->ret = dup_lego_mm(tsk, parent, reply);
	if (reply->ret) {
		WARN_ONCE(1, "Fail to dup mm");
		free_lego_task_struct(tsk);
		return;
	}

	/* All done, insert into hashtable */
	reply->ret = ht_insert_lego_task(tsk);
	if (reply->ret) {
		lego_mmput(tsk->mm);
		free_lego_task_struct(tsk);

		/* Same process? */
		if (likely(reply->ret == -EEXIST))
			reply->ret = 0;
		return;
	}

	/*
	 * This is essentially [struct fork_reply_struct].
	 * We only want to reply what we got here:
	 */
	reply_size = sizeof(int) + sizeof(u32) +
		     reply->vma_count * sizeof(struct fork_vmainfo);
	tb_set_tx_size(tb, reply_size);
}
