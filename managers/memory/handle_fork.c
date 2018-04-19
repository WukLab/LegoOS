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

#ifdef CONFIG_DEBUG_HANDLE_FORK
#define fork_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)

#define dump_both_vmas(mm, oldmm)		\
	do {					\
		dump_all_vmas_simple(mm);	\
		dump_all_vmas_simple(oldmm);	\
	} while (0)
#else
static inline void fork_debug(const char *fmt, ...) { }
#define dump_both_vmas(mm, oldmm)	do { } while (0)
#endif

/*
 * This function duplicate mmap layout from parent,
 * which is the basic COW guarantee of fork().
 *
 * The whole lego_mm_struct will be replcaed by a new one
 * when execve() is called. This is also what execve() guarantees.
 * Check managers/memory/loader/vm.c for detail.
 */
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

static int 
dup_lego_mmap_single_vmatree(struct lego_mm_struct *mm, struct lego_mm_struct *oldmm,
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

static int 
dup_lego_mmap_local_vmatree(struct lego_mm_struct *mm, struct lego_mm_struct *oldmm)
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

static int distribute_m2m_fork(struct lego_task_struct *tsk, 
			       struct lego_task_struct *parent, u64 mnode)
{
	int ret, reply;
	struct m2m_fork_struct info;

	info.pid = parent->pid;
	info.tgid = tsk->pid;
	info.prcsr_nid = tsk->node;

	ret = net_send_reply_timeout(mnode, M2M_FORK, (void *)&info, 
			sizeof(struct m2m_mmap_struct), (void *)&reply, 
			sizeof(int), false, FIT_MAX_TIMEOUT_SEC);

	return ret < 0 ? ret : reply;
}

int handle_m2m_fork(struct m2m_fork_struct *payload, u64 desc, 
		    struct common_header *hdr, void *tx)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	u32 tgid = payload->tgid;
	u32 prcsr_nid = payload->prcsr_nid;
	struct lego_task_struct *parent;
	struct lego_task_struct *tsk;
	u32 *reply = tx;
	
	vma_debug("%s, nid: %d, pid: %d, tgid: %d, prcsr_nid: %d",
		   __func__, nid, pid, tgid, prcsr_nid);

	parent = find_lego_task_by_pid(prcsr_nid, pid);
	if (unlikely(!parent)) {
		*reply = -ESRCH;
		goto out;
	}

	tsk = alloc_lego_task_struct();
	if (unlikely(!tsk)) {
		*reply = -ENOMEM;
		goto out;
	}

	tsk->pid = tgid;
	tsk->node = prcsr_nid;
	mem_set_memory_home_node(tsk, nid);

	tsk->mm = lego_mm_alloc(tsk, NULL);
	if (!tsk->mm) {
		*reply = -ENOMEM;
		goto out;
	}

	/* All done, insert into hashtable */
	*reply = ht_insert_lego_task(tsk);
	if (*reply) {
		lego_mmput(tsk->mm);
		free_lego_task_struct(tsk);

		/* Same process? */
		if (likely(*reply == -EEXIST))
			*reply = 0;
		goto out;
	}

	if (down_write_killable(&parent->mm->mmap_sem)) {
		*reply = -EINTR;
		goto out;
	}

	down_write(&tsk->mm->mmap_sem);

	/* task struct is prepared, start duplication */
	*reply = dup_lego_mmap_local_vmatree(tsk->mm, parent->mm);

	up_write(&tsk->mm->mmap_sem);
	up_write(&parent->mm->mmap_sem);

out:
	ibapi_reply_message(reply, sizeof(u32), desc);
	return 0;
}

static int dup_lego_mmap(struct lego_mm_struct *mm, struct lego_mm_struct *oldmm)
{
	int ret = 0, mnode = 0;

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

	for (mnode = 0; mnode < NODE_COUNT; mnode++) {
		struct distvm_node *node = oldmm->node_map[mnode];
		struct distvm_node **newnode = &mm->node_map[mnode];
		
		if (!node)
			continue;

		/* homenode copys everything */
		*newnode = kzalloc(sizeof(struct distvm_node), GFP_KERNEL);
		INIT_LIST_HEAD(&(*newnode)->list);
		dup_lego_mmap_local_vmatree(mm, oldmm);

		/* send request ot other nodes */
		if (!is_local(mnode))
			distribute_m2m_fork(oldmm->task, mm->task, mnode);
	}

out:
	up_write(&mm->mmap_sem);
	up_write(&oldmm->mmap_sem);

	return ret;
}
#else 
static int dup_lego_mmap(struct lego_mm_struct *mm,
			 struct lego_mm_struct *oldmm)
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
	for (mpnt = oldmm->mmap; mpnt; mpnt = mpnt->vm_next) {
		struct lego_file *file;

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
	}

	ret = 0;
out:
	up_write(&mm->mmap_sem);
	up_write(&oldmm->mmap_sem);
	return ret;
}
#endif /* CONFIG_DISTRIBUTED_VMA */

#ifdef CONFIG_DEBUG_HANDLE_FORK
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
#define debug_fork_dump_mm(foo, bar, a)	do { } while(0)
#endif

static int dup_lego_mm(struct lego_task_struct *t,
		       struct lego_task_struct *parent)
{
	struct lego_mm_struct *mm, *oldmm;
	int err;

	mm = lego_mm_alloc(t, parent);
	if (!mm)
		return -ENOMEM;
	t->mm = mm;

	if (parent) {
		oldmm = parent->mm;
		err = dup_lego_mmap(mm, oldmm);
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

int handle_p2m_fork(struct p2m_fork_struct *payload, u64 desc,
		    struct common_header *hdr, void *tx)
{
	unsigned int nid = hdr->src_nid;
	unsigned int tgid = payload->tgid;
	unsigned int parent_tgid = payload->parent_tgid;
	struct lego_task_struct *tsk, *parent;
	u32 *retbuf = tx;

	fork_debug("nid:%u,pid:%u,tgid:%u,parent_tgid:%u",
		nid, payload->pid, tgid, parent_tgid);

	parent = find_lego_task_by_pid(nid, parent_tgid);
	if (!parent && parent_tgid != 1)
		WARN_ONCE(1, "From processor-daemon?");

	tsk = alloc_lego_task_struct();
	if (!tsk) {
		*retbuf = -ENOMEM;
		goto reply;
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
	*retbuf = dup_lego_mm(tsk, parent);
	if (*retbuf) {
		free_lego_task_struct(tsk);
		goto reply;
	}

	/* All done, insert into hashtable */
	*retbuf = ht_insert_lego_task(tsk);
	if (*retbuf) {
		lego_mmput(tsk->mm);
		free_lego_task_struct(tsk);

		/* Same process? */
		if (likely(*retbuf == -EEXIST))
			*retbuf = 0;
		goto reply;
	}

	*retbuf = 0;
reply:
	fork_debug("reply: %d:%s", *retbuf, perror(*retbuf));
	ibapi_reply_message(retbuf, 4, desc);
	return 0;
}
