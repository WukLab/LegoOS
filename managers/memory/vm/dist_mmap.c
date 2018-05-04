/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * function naming convention:
 * vmpool: functions that manipulate VM_GRANULARIY aligned free memory
 * distribute: functions that genereate requests to other memory comp
 * homenode: functions that can only be called at homenode
 * vmatree: since vma rbtree root can span cross multiple ranges,
 *	    instead of calling vm range, we use vma tree
 *
 * variable naming convention:
 * root: usually indicates the root of one vma rbtree
 * range: address aligned to VM_GRANULARIY, implicating the begin of
 *	  vma tree and only used for constructing vma tree
 * node: one entry of node_map under lego_mm_struct, one node
 *	 corresponding to one memory component, containing a list
 *	 of vma tree roots, sorted by gaps reversely
 *
 * return value convetion:
 * if functions return either addr or error value, their return type
 * is unsigned long. if functions only return status, then their return
 * type is int
 */

#include <lego/slab.h>
#include <lego/comp_common.h>
#include <lego/fit_ibapi.h>
#include <lego/sysinfo.h>

#include <memory/vm.h>
#include <memory/task.h>
#include <memory/distvm.h>
#include <memory/file_types.h>
#include <memory/stat.h>

static int vmpool_init(struct lego_mm_struct *mm, bool is_copy)
{
	struct rb_root *root = &mm->vmpool_rb;
	struct vm_pool_struct *new;
	new = kzalloc(sizeof(struct vm_pool_struct), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	if (is_copy)
		return 0;

	new->pool_start = 0;
	new->pool_end = VMR_ALIGN(TASK_SIZE);

	rb_link_node(&new->vmr_rb, NULL, &root->rb_node);
	rb_insert_color(&new->vmr_rb, root);
	return 0;
}

int distvm_init(struct lego_mm_struct *mm)
{
	mm->vmrange_map = kzalloc(MEMORY_VMR_SIZE, GFP_KERNEL);
	if (unlikely(!mm->vmrange_map))
		return -ENOMEM;

	return 0;
}

int distvm_init_homenode(struct lego_mm_struct *mm, bool is_copy)
{
	struct distvm_node **node;
	/* assign new node infos array */
	mm->node_map = kzalloc(NODEMAP_SIZE, GFP_KERNEL);
	if (unlikely(!mm->node_map))
		return -ENOMEM;

	/* initialize list for homenode */
	node = &mm->node_map[LEGO_LOCAL_NID];
	*node = kzalloc(sizeof(struct distvm_node), GFP_KERNEL);
	if (unlikely(!(*node)))
		return -ENOMEM;
	INIT_LIST_HEAD(&(*node)->list);

	/* initiate free pool */
	mm->vmpool_rb = RB_ROOT;
	if (vmpool_init(mm, is_copy))
		return -ENOMEM;

#ifdef CONFIG_VMA_CACHE_AWARENESS
	mm->addr_offset = 0;
#endif

	return distvm_init(mm);
}

void distvm_exit(struct lego_mm_struct *mm)
{
	struct vma_tree **map = mm->vmrange_map;
	int i, ret;

	for (i = 0; i < VMR_COUNT; i++) {
		struct vma_tree *root;
		unsigned long end, unused;
		if (!map[i])
			continue;

		root = get_vmatree_by_idx(mm, i);
		i = last_vmr_idx(map[i]->end);

		end = min((unsigned long)root->end, (unsigned long)TASK_SIZE);
		load_vma_context(mm, map[i]);
		ret = distvm_munmap(mm, map[i]->begin,
				    end - map[i]->begin, &unused);
		VMA_BUG_ON(ret);
	}
	kfree(mm->vmrange_map);
	mm->vmrange_map = NULL;
}

void distvm_exit_homenode(struct lego_mm_struct *mm)
{
	struct distvm_node **node_map = mm->node_map;
	struct vm_pool_struct *pos, *n;
	int i;

	for (i = 0; i < NODE_COUNT; i++) {
		if (node_map[i])
			kfree(node_map[i]);
	}
	kfree(mm->node_map);
	mm->node_map = NULL;

	rbtree_postorder_for_each_entry_safe(pos, n, &mm->vmpool_rb, vmr_rb) {
		kfree(pos);
		pos = NULL;
	}
	mm->vmpool_rb = RB_ROOT;

	distvm_exit(mm);
}

static inline void
vmpool_overlap_check(unsigned long pstart, unsigned long pend,
		     unsigned long start, unsigned long end)
{
	/*
	 * For debug, warn if any overlap between request and
	 * already freed pool
	 * CASE 1:	|start.................end|
	 *			|pstart...............pend|
	 *
	 * CASE 2:		|start.................end|
	 *		|pstart...............pend|
	 */
	VMA_WARN(pstart > start && pstart < end,
			"BUG! vm pools bug case 1 discovered\n");
	VMA_WARN(pend > start && pend < end,
			"BUG! vm pools bug case 2 discovered\n");
}

/* retieve start and end should be VM_GRANULARITY aligned */
int
vmpool_retrieve(struct rb_root *root, unsigned long start, unsigned long end)
{
	struct rb_node **node = &(root->rb_node), *parent = NULL;
	struct vm_pool_struct *new;

	vma_trace("%s, start: %lx, end: %lx\n", __func__, start, end);

	/* TASK_SIZE is not vm range aligned */
	if (end == TASK_SIZE)
		end = VMR_ALIGN(end);
	if (VMR_ALIGN(start) > start || VMR_ALIGN(end) > end)
		return -EINVAL;

	while(*node) {
		struct rb_node *adj;
		struct vm_pool_struct *pool, *adjpool = NULL;
		pool = rb_entry(*node, struct vm_pool_struct, vmr_rb);

		vmpool_overlap_check(pool->pool_start,
				     pool->pool_end, start, end);

		/* Good cases, don't even need to create a new tree node,
		 * and potentially remove tree node
		 * CASE 1:	|start.......end|
		 *				|pstart.....pend|
		 *
		 * CASE 2:			|start.......end|
		 *		|pstart.....pend|
		 */
		if (pool->pool_start == end) {
			pool->pool_start = start;

			/* check potential merge */
			adj = rb_prev(*node);
			/* currect pool is the lowest pool */
			if (!adj)
				return 0;

			adjpool = rb_entry(adj, struct vm_pool_struct, vmr_rb);
			/* start not connected with end of previous hole */
			if (adjpool->pool_end < start)
				return 0;

			/* finally, good case 1 */
			pool->pool_start = adjpool->pool_start;
			rb_erase(adj, root);
			kfree(adjpool);
			adjpool = NULL;
			return 0;
		} else if (pool->pool_end == start) {
			/* mirror of above */
			pool->pool_end = end;

			adj = rb_next(*node);
			if (!adj)
				return 0;

			adjpool = rb_entry(adj, struct vm_pool_struct, vmr_rb);
			/* start not connected with end of next hole */
			if (adjpool->pool_start > end)
				return 0;

			/* finally, good case 2 */
			pool->pool_end = adjpool->pool_end;
			rb_erase(adj, root);
			kfree(adjpool);
			adjpool = NULL;
			return 0;
		} else {
			/* when request not adjacent to current pool, search
			 * CASE 1:	|start.......end|
			 *				   |pstart.....pend|
			 *
			 * CASE 2:			   |start.......end|
			 *		|pstart.....pend|
			 */
			parent = *node;
			if (pool->pool_start > end)
				node = &((*node)->rb_left);
			else
				node = &((*node)->rb_right);
		}
	}

	/* request not adjacent to any pool */
	new = kmalloc(sizeof(struct vm_pool_struct), GFP_KERNEL);
	new->pool_start = start;
	new->pool_end = end;

	/* add new node and rebalance */
	rb_link_node(&new->vmr_rb, parent, node);
	rb_insert_color(&new->vmr_rb, root);
	return 0;
}

/*
 * Find the first VM poolwhich satisfies  addr < pool_end,  NULL if none.
 * addr argument should be VM_GRANULARITY aligned
 */
static struct vm_pool_struct *
vmpool_find(struct rb_root *root, unsigned long addr)
{
	struct rb_node *node = root->rb_node;
	struct vm_pool_struct *pool = NULL;

	vma_trace("%s, addr: %lx\n", __func__, addr);
	BUG_ON(VMR_ALIGN(addr) > addr);

	while(node) {
		struct vm_pool_struct *tmp;
		tmp = rb_entry(node, struct vm_pool_struct, vmr_rb);

		if (tmp->pool_end > addr) {
			pool = tmp;
			if (tmp->pool_start <= addr)
				break;
			node = node->rb_left;
		} else
			node = node->rb_right;
	}

	return pool;
}

/*
 * Cases Enumeration when address is spscified
 * General rule, any free pool and request overlap
 * will result free pool being deducted
 * Case 1:	Free			|...........|
 *		Request		|...........|
 *		Final Free		    |.......|
 *
 * Case 2:	Free		|...........|
 *		Request			|...........|
 *		Final Free	|.......|
 *
 * Case 3:	Free		    |...........|
 *		Request		|...................|
 *		Final Free	Nothing, struct free
 *
 * Case 4:	Free		|...................|
 *		Request		      |.......|
 *		Final Free	|.....|       |.....|
 */
unsigned long vmpool_alloc(struct rb_root *root, unsigned long addr,
			   unsigned long len, unsigned long flag)
{
	struct vm_pool_struct *pool = NULL;
	struct rb_node *node;
	unsigned long end = VMR_ALIGN(addr + len);
	unsigned long begin = VMR_OFFSET(addr);
	unsigned long chop_begin;
	len = end - begin;

	vma_trace("%s, addr: %lx, len: %lx, flag: %lx\n",
			__func__, addr, len, flag & MAP_FIXED);
	VMA_BUG_ON(begin > VMR_ALIGN(TASK_SIZE));
	VMA_BUG_ON(begin + len > VMR_ALIGN(TASK_SIZE));

	if (!(flag & MAP_FIXED)) {
		for (node = rb_last(root); node; node = rb_prev(node)) {
			/* look for pool that satisfy request len */
			pool = rb_entry(node, struct vm_pool_struct, vmr_rb);
			if (pool->pool_end - pool->pool_start >= len)
				break;
		}
		if (!pool)
			return -ENOMEM;

		/* allocate from higher address */
		pool->pool_end -= len;
		begin = pool->pool_end;
		if (pool->pool_end == pool->pool_start) {
			rb_erase(&pool->vmr_rb, root);
			kfree(pool);
		}
		return begin;
	}

	/* when address is specified */
	pool = vmpool_find(root, begin);
	if (!pool)
		return addr;
	chop_begin = max((unsigned long)pool->pool_start, begin);
	while (chop_begin < end) {
		struct rb_node *next;
		if (chop_begin == pool->pool_start) {
			/* Case 1 */
			if (end < pool->pool_end) {
				pool->pool_start = end;
				return addr;
			}

			/* Case 3 */
			next = rb_next(&pool->vmr_rb);
			rb_erase(&pool->vmr_rb, root);
			if (end == pool->pool_end) {
				kfree(pool);
				return addr;
			}
			kfree(pool);
		} else {
			struct vm_pool_struct *newpool;
			struct rb_node *parent, **rblink;

			/* Case 4 */
			if (end >= pool->pool_end)
				goto crop_pool_end;

			/* create new pool */
			newpool = kmalloc(sizeof(struct vm_pool_struct),
					  GFP_KERNEL);
			if (!newpool)
				return -ENOMEM;
			newpool->pool_start = end;
			newpool->pool_end = pool->pool_end;
			pool->pool_end = chop_begin;

			/* add new node and rebalance */
			parent = &pool->vmr_rb;
			rblink = &pool->vmr_rb.rb_right;
			while (*rblink) {
				parent = *rblink;
				rblink = &parent->rb_left;
			}
			rb_link_node(&newpool->vmr_rb, parent, rblink);
			rb_insert_color(&newpool->vmr_rb, root);
			return addr;

crop_pool_end:
			/* Case 2 */
			pool->pool_end = chop_begin;
		}
		/*
		 * Cases above can repeatedly appear when
		 * request across several free pool
		 */
		if (pool)
			next = rb_next(&pool->vmr_rb);
		if (!next)
			return addr;
		pool = rb_entry(next, struct vm_pool_struct, vmr_rb);
		chop_begin = pool->pool_start;
	}
	return addr;
}

static unsigned long
distribute_mmap(struct lego_task_struct *tsk, unsigned long new_range,
		unsigned long addr, unsigned long len, unsigned long prot,
		unsigned long flags, vm_flags_t vm_flags, unsigned long pgoff,
		int mnode, struct lego_file *file, unsigned long *max_gap)
{
#ifdef CONFIG_FIT
	unsigned long ret;
	struct m2m_mmap_struct send;
	struct m2m_mmap_reply_struct reply;

	send.pid = tsk->pid;
	send.prcsr_nid = tsk->node;
	send.new_range = new_range;
	send.addr = addr;
	send.len = len;
	send.prot = prot;
	send.flags = flags;
	send.vm_flags = vm_flags;
	send.pgoff = pgoff;
	if (file)
		memcpy(&send.f_name, &file->filename, MAX_FILENAME_LENGTH);

	ret = net_send_reply_timeout(mnode, M2M_MMAP, (void *)&send,
			sizeof(struct m2m_mmap_struct), (void *)&reply,
			sizeof(struct m2m_mmap_reply_struct),
			false, DEF_NET_TIMEOUT);

	if (ret != sizeof(reply))
		return -EIO;

	*max_gap = reply.max_gap;
	return reply.addr;
#else
	return -ETIMEDOUT;
#endif
}

static int
distribute_munmap(struct lego_task_struct *tsk, unsigned long begin,
		  unsigned long len, int mnode, unsigned long *max_gap)
{
#ifdef CONFIG_FIT
	int ret;
	struct m2m_munmap_struct send;
	struct m2m_munmap_reply_struct reply;

	send.pid = tsk->pid;
	send.prcsr_nid = tsk->node;
	send.begin = begin;
	send.len = len;

	ret = net_send_reply_timeout(mnode, M2M_MUNMAP, (void *)&send,
			sizeof(struct m2m_munmap_struct), (void *)&reply,
			sizeof(struct m2m_munmap_reply_struct),
			false, DEF_NET_TIMEOUT);

	if (ret != sizeof(reply))
		return -EIO;

	*max_gap = reply.max_gap;
	return reply.status;
#else
	return -ETIMEDOUT;
#endif
}

static int
distribute_mremap_grow(struct lego_task_struct *tsk, unsigned long addr,
		       unsigned long old_len, unsigned long new_len, int mnode,
		       unsigned long *max_gap)
{
#ifdef CONFIG_FIT
	int ret;
	struct m2m_mremap_grow_struct send;
	struct m2m_mremap_grow_reply_struct reply;

	send.pid = tsk->pid;
	send.prcsr_nid = tsk->node;
	send.addr = addr;
	send.old_len = old_len;
	send.new_len = new_len;

	ret = net_send_reply_timeout(mnode, M2M_MREMAP_GROW, (void *)&send,
			sizeof(struct m2m_mremap_grow_struct), (void *)&reply,
			sizeof(struct m2m_mremap_grow_reply_struct), false,
			DEF_NET_TIMEOUT);

	if (ret != sizeof(reply))
		return -EIO;

	*max_gap = reply.max_gap;
	return reply.status;
#else
	return -ETIMEDOUT;
#endif
}

static unsigned long
distribute_mremap_move(struct lego_task_struct *tsk, unsigned long old_addr,
		       unsigned long old_len, unsigned long new_len,
		       unsigned long new_range, int mnode,
		       unsigned long *old_max_gap, unsigned long *new_max_gap)
{
#ifdef CONFIG_FIT
	unsigned long ret;
	struct m2m_mremap_move_struct send;
	struct m2m_mremap_move_reply_struct reply;

	send.pid = tsk->pid;
	send.prcsr_nid = tsk->node;
	send.old_addr = old_addr;
	send.old_len = old_len;
	send.new_len = new_len;
	send.new_range = new_range;

	ret = net_send_reply_timeout(mnode, M2M_MREMAP_MOVE, (void *)&send,
			sizeof(struct m2m_mremap_move_struct), (void *)&reply,
			sizeof(struct m2m_mremap_move_reply_struct), false,
			DEF_NET_TIMEOUT);

	if (ret != sizeof(reply))
		return -EIO;

	*old_max_gap = reply.old_max_gap;
	*new_max_gap = reply.new_max_gap;
	return reply.new_addr;
#else
	return -ETIMEDOUT;
#endif
}

static int
distribute_mremap_move_split(struct lego_task_struct *tsk,
	unsigned long old_addr, unsigned long old_len,
	unsigned long new_addr, unsigned long new_len, int mnode,
	unsigned long *old_max_gap, unsigned long *new_max_gap)
{
#ifdef CONFIG_FIT
	int ret;
	struct m2m_mremap_move_split_struct send;
	struct m2m_mremap_move_split_reply_struct reply;

	send.pid = tsk->pid;
	send.prcsr_nid = tsk->node;
	send.old_addr = old_addr;
	send.new_addr = new_addr;
	send.old_len = old_len;
	send.new_len = new_len;

	ret = net_send_reply_timeout(mnode, M2M_MREMAP_MOVE_SPLIT,
			(void *)&send, sizeof(send), (void *)&reply,
			sizeof(reply), false, DEF_NET_TIMEOUT);

	if (ret != sizeof(reply))
		return -EIO;

	*old_max_gap = reply.old_max_gap;
	*new_max_gap = reply.new_max_gap;
	return reply.new_addr;
#else
	return -ETIMEDOUT;
#endif
}

static int
distribute_findvma(struct lego_task_struct *tsk, unsigned long begin,
		   unsigned long end, int mnode)
{
#ifdef CONFIG_FIT
	int ret;
	struct m2m_findvma_struct send;
	struct m2m_findvma_reply_struct reply;

	send.pid = tsk->pid;
	send.prcsr_nid = tsk->node;
	send.begin = begin;
	send.end = end;

	ret = net_send_reply_timeout(mnode, M2M_FINDVMA, (void *)&send,
			sizeof(struct m2m_findvma_struct), (void *)&reply,
			sizeof(struct m2m_findvma_reply_struct),
			false, DEF_NET_TIMEOUT);

	if (ret != sizeof(reply))
		return -EIO;

	return reply.vma_exist;
#else
	return -ETIMEDOUT;
#endif
}

static inline void extract_reply(struct consult_reply *reply,
				 int *nodecount, struct alloc_scheme **scheme)
{
	*scheme = reply->scheme;
	*nodecount = reply->count;
}

static int consult_gmm(unsigned long request,
		       unsigned long flag, struct consult_reply *reply)
{
	int ret = 0;

#ifndef CONFIG_VMA_MEMORY_UNITTEST

#ifdef CONFIG_GMM

	struct manager_sysinfo info;
	struct consult_info send;

	manager_meminfo(&info);
	send.totalram = info.totalram;
	send.freeram = info.freeram;
	send.nr_request = atomic_long_read(&memory_manager_stats.stat[HANDLE_PCACHE_MISS]);
	send.len = request;

	ret = net_send_reply_timeout(CONFIG_GMM_NODEID, M2MM_CONSULT,
				&send, sizeof(struct consult_info),
				reply, sizeof(struct consult_reply),
				false, DEF_NET_TIMEOUT);
	if (ret > 0)
		ret = 0;

#else

	reply->count = 1;
	reply->scheme[0].nid = MY_NODE_ID;
	reply->scheme[0].len = request;

#endif /* CONFIG_GMM */

#else

	ret = consult_fake_gmm(request, reply);

#endif /* CONFIG_VMA_MEMORY_UNITTEST */

	vma_trace("%s, request len: %lx, ret: %d\n", __func__, request, ret);

	return ret;
}

/* return value: 0, no intersect. 1 intersect, other value is an error */
int find_dist_vma_intersection(struct lego_mm_struct *mm,
			       unsigned long begin, unsigned long end)
{
	struct vma_tree **map = mm->vmrange_map;
	struct vma_tree *root;
	unsigned long begin_idx = vmr_idx(begin);
	unsigned long end_idx = vmr_idx(VMR_ALIGN(end));
	unsigned long cur, prev, idx;
	int ret = 0;

	vma_trace("%s, begin: %lx, end: %lx\n", __func__, begin, end);

	/* get the first mapped range */
	for (idx = begin_idx; idx < end_idx; idx++) {
		if (map[idx])
			break;
	}

	/*
	 * if only one tree from begin to end,
	 * we can send find vma request to the tree.
	 * if multiple trees exist, definitely overlapped
	 */
	cur = map[idx]->mnode;
	for (; idx < end_idx; idx++) {
		/*
		 * if some range is not assigned between begin and end
		 * there is definitely intersect
		 */
		if (!map[idx])
			return 1;

		prev = cur;
		cur = map[idx]->mnode;
		if (cur != prev)
			return 1;
	}

	/*
	 * at this point we can either do find_vma locally
	 * or send request to remote
	 */
	root = get_vmatree_by_idx(mm, last_vmr_idx(end));
	if (is_local(root->mnode)) {
		load_vma_context(mm, root);
		if (find_vma_intersection(mm, begin, end))
			ret = 1;
		save_vma_context(mm, root);
	} else {
		ret = distribute_findvma(mm->task, begin, end, root->mnode);
	}
	return ret;
}

void max_gap_update(struct vma_tree *root)
{
	struct rb_node *node;
	struct vm_area_struct *vma, *lastvma = NULL;

	/*
	 * look up the gap between last vma end and with in range end
	 * (stack can be beyond range), since mmap internal
	 * vma_gap_update only look up gap at the left side of vma
	 *
	 * although it's a loop, typically it will only loop once
	 */
	for(node = rb_last(&root->vm_rb); node; node = rb_prev(node)) {
		vma = rb_entry_safe(node, struct vm_area_struct, vm_rb);
		if (!vma) {
			root->max_gap = root->end - root->begin;
			return;
		}
		if (vma->vm_end <= root->end) {
			lastvma = vma;
			break;
		}
	}
	if (!lastvma)
		root->max_gap = root->end - root->begin;
	else {
		/* here, definitely at least one vma, don't need NULL check */
		node = root->vm_rb.rb_node;
		vma = rb_entry(node, struct vm_area_struct, vm_rb);
		root->max_gap = max((long)(root->end - lastvma->vm_end),
				    (long)vma->rb_subtree_gap);
	}
}

void sort_node_gaps(struct lego_mm_struct *mm, struct vma_tree *root)
{
	struct distvm_node **node = &mm->node_map[root->mnode];
	struct list_head *head;
	struct vma_tree *pos;

	if (!(*node)) {
		*node = kzalloc(sizeof(struct distvm_node), GFP_KERNEL);
		INIT_LIST_HEAD(&(*node)->list);
	}

	list_del_init(&root->list);

	head = (*node)->list.prev;
	list_for_each_entry(pos, &(*node)->list, list) {
		if (root->max_gap >= pos->max_gap) {
			head = pos->list.prev;
			break;
		}
	}
	list_add(&root->list, head);
}

static void
remove_single_vmatree(struct lego_mm_struct *mm, struct vma_tree *root)
{
	struct vmr_map_struct *reply = NULL;

	VMA_BUG_ON(!RB_EMPTY_ROOT(&root->vm_rb));
	VMA_BUG_ON(root->mmap);

	set_vmrange_map(mm, root->begin, root->end - root->begin, NULL);

	if (!is_homenode(mm->task))
		goto free_root;

	/* homenode only operations */
	reply = get_available_reply_entry(mm);
	if (!reply)
		goto free_root;
	reply->mnode = (vmr16)LEGO_LOCAL_NID;
	reply->start = root->begin;
	reply->len = root->end - root->begin;

free_root:
	if (!list_empty(&root->list))
		list_del(&root->list);
	kfree(root);
}

static int unmap_vmatrees(struct lego_mm_struct *mm,
			  unsigned long begin, unsigned long len)
{
	unsigned long end = begin + len;
	unsigned long idx = vmr_idx(begin);
	int ret;

	vma_trace("%s, begin: %lx, len: %lx\n", __func__, begin, len);
	/*
	 * look up all the vma_tree in between begin and
	 * begin + len
	 */
	while (idx < vmr_idx(VMR_ALIGN(end))) {
		struct vma_tree *root = get_vmatree_by_idx(mm, idx);
		unsigned long chop_begin, chop_end;

		if (!root) {
			idx++;
			continue;
		}

		chop_begin = max((unsigned long)root->begin, begin);
		chop_end = min((unsigned long)root->end, end);
		idx = vmr_idx(VMR_ALIGN(chop_end));

		vma_trace("%s, unmap begin: %lx, end: %lx\n",
			  __func__, chop_begin, chop_end);

		root = get_vmatree_by_addr(mm, chop_begin);
		if (is_local(root->mnode)) {
			struct vm_area_struct *vma;

			vma = find_vma(mm, chop_begin);
			if (!vma || chop_end <= vma->vm_start)
				continue;

			load_vma_context(mm, root);
			ret = do_munmap(mm, chop_begin,
					chop_end - chop_begin);
			save_update_vma_context(mm, root);
			if (ret)
				return ret;
		} else {
			unsigned long reply_max_gap;
			VMA_BUG_ON(!is_homenode(mm->task));

			ret = distribute_munmap(mm->task, chop_begin,
						chop_end - chop_begin,
						root->mnode, &reply_max_gap);
			if (ret)
				return ret;
			root->max_gap = reply_max_gap;
		}
		if (root->max_gap == root->end - root->begin && !root->mmap)
			remove_single_vmatree(mm, root);
	}
	return 0;
}

/* TODO: current statically set stack limit */
#define MIN_GAP	(128*1024*1024UL)

int map_vmatrees(struct lego_mm_struct *mm, int mnode, unsigned long addr,
		 unsigned long len, unsigned long flag)
{
	struct vma_tree **map = mm->vmrange_map;
	struct vma_tree *root;
	struct vmr_map_struct *entry = NULL;
	unsigned long begin = VMR_OFFSET(addr);
	unsigned long end = addr + len - 1;	/* an inclusive boundary */
	unsigned long idx = vmr_idx(begin);
	unsigned long end_idx = vmr_idx(end);

	vma_trace("%s, mm: %p, addr: %lx, len: %lx, mnode: %d, flag: %lx\n",
			__func__, mm, addr, len, mnode, flag);

	/* unmap overlap */
	if (flag & MAP_FIXED) {
		int ret = unmap_vmatrees(mm, addr, len);
		if (ret)
			return ret;
	}

	/*
	 * since addr and len may not be VM_GRANULARITY aligned
	 * it's possible that first covered range and last covered
	 * range is not totally unmapped, thus, no action for
	 * these two ranges
	 */
	if (get_vmatree_by_idx(mm, idx)) {
		begin += VM_GRANULARITY;
		idx = vmr_idx(begin);
	}
	if (get_vmatree_by_idx(mm, end_idx)) {
		end = end >= VM_GRANULARITY ? end - VM_GRANULARITY : 0;
		end_idx = vmr_idx(end);
	}
	if ((long)end_idx < (long)idx)
		return 0;

	/*
	 * check if possible to merge existing tree, either with smaller
	 * address or with larger address, merge to both will
	 * possibly result overhead in move vma struct
	 */
	if (end_idx + 1 < VMR_COUNT && map[end_idx + 1] &&
		      map[end_idx + 1]->mnode == mnode) {
		root = get_vmatree_by_idx(mm, end_idx + 1);
		root->begin = begin;
		if (is_local(root->mnode)) {
			/*
			 * adding the new gap to the start of first vma
			 * within target range
			 */
			struct rb_node *first = rb_first(&root->vm_rb);
			struct vm_area_struct *vma = rb_entry(first,
					struct vm_area_struct, vm_rb);
			if (!vma)
				goto map_new_addr;
			vma_gap_update(vma);
			max_gap_update(root);
		}
		goto map_new_addr;
	}

	if (idx > 0 && map[idx - 1] && map[idx - 1]->mnode == mnode) {
		root = get_vmatree_by_idx(mm, idx - 1);
		root->end = VMR_ALIGN(end);

		if (is_local(root->mnode))
			max_gap_update(root);
		goto map_new_addr;
	}

	root = kmalloc(sizeof(struct vma_tree), GFP_KERNEL);
	if (!root)
		return -ENOMEM;

	root->vm_rb = RB_ROOT;
	root->mmap = NULL;
	root->begin = max(begin, PAGE_SIZE);
	root->highest_vm_end = begin;
	root->end = min((unsigned long)VMR_ALIGN(end),
			(unsigned long)PAGE_ALIGN(TASK_SIZE-MIN_GAP));
	root->flag = flag & MAP_FIXED;
	root->max_gap = root->end - root->begin;
	root->mnode = mnode;
	INIT_LIST_HEAD(&root->list);

map_new_addr:
	set_vmrange_map(mm, begin, VMR_ALIGN(end) - begin, root);
	if (!is_homenode(mm->task))
		goto out;

	/* homenode only operation */
	entry = get_available_reply_entry(mm);
	VMA_BUG_ON(!entry);
	entry->mnode = (vmr16)root->mnode;
	entry->start = begin;
	entry->len = VMR_ALIGN(end) - begin;

out:
	vma_trace("%s, begin: %lx, len: %lx, map[%lx]: %p\n", __func__,
		  root->begin, root->end - root->begin,
		  vmr_idx(root->begin), map[vmr_idx(begin)]);
	return 0;
}

static void update_nodegaps_freepool(struct lego_mm_struct *mm,
				     unsigned long begin, unsigned long len)
{
	unsigned long end = begin + len;
	unsigned long idx = vmr_idx(begin);

	vma_trace("%s, begin: %lx, len: %lx\n", __func__, begin, len);

	while (idx < vmr_idx(VMR_ALIGN(end))) {
		struct vma_tree *root = get_vmatree_by_idx(mm, idx);
		unsigned long free_begin;
		unsigned long free_end;

		if (!root) {
			idx++;
			continue;
		}
		idx = vmr_idx(VMR_ALIGN(min((unsigned long)root->end, end)));

		if (root->max_gap == root->end - root->begin && !root->mmap) {
			/* whole tree is empty, back to free pool */
			free_begin = root->begin;
			free_end = root->end;
			remove_single_vmatree(mm, root);
			vmpool_retrieve(&mm->vmpool_rb, free_begin, free_end);
		} else {
			sort_node_gaps(mm, root);
		}
	}
}

/*
 * mnode is used for search max gap in one memory node,
 * useful only when givn address and len falls into one
 * continous range in one node, no effect when they cross
 * multiple nodes
 * Therefore, mnode should be which 'addr' is in
 *
 * return addr only used for map range to tree and is VMR aligned
 */
static unsigned long
get_unmapped_range(struct lego_mm_struct *mm, unsigned long addr,
		unsigned long len, int mnode, unsigned long flag, int nr_split)
{
	struct distvm_node *node = mm->node_map[mnode];
	struct vma_tree *pos, *root = NULL;

	vma_trace("%s, addr: %lx, len: %lx, mnode: %d, "
		  "flag: %lx, nr_split: %x\n",
		  __func__, addr, len, mnode, flag, nr_split);

	if (!is_node_valid(mnode)) {
		vma_trace("memory node invalid, GMM didn't"
			  "provide a correct value\n");
		/* TODO: Current set to BUG, later, we can
		 * change it by ignoring the request */
		BUG();
	}

	if (flag & MAP_FIXED || nr_split > 1)
		goto get_free_pool;

	/* request with advice address */
	if (addr) {
		root = get_vmatree_by_addr(mm, addr);

		/*
		 * only follow address if it's same as
		 * gmm suggested memory node
		 */
		if (root && root->mnode != mnode)
			goto get_existing_range;

		/* find out if there are existing vma overlapped */
		if (TASK_SIZE - len >= addr &&
		    !find_dist_vma_intersection(mm, addr, addr + len))
			goto get_free_pool;
	}

get_existing_range:
	/*
	 * check if there's still free space within given vm range
	 * list is sorted by gaps in reversed order
	 */
	root = NULL;
	if (!node)
		goto get_free_pool;

	list_for_each_entry(pos, &node->list, list) {
		if (pos->flag & MAP_FIXED)
			continue;
		if (pos->max_gap >= len)
			root = pos;
		if (pos->max_gap < len)
			break;
	}

	if (root) {
		/* check if max_gap is gap reserved for stack */
		struct rb_node *rb_node = rb_last(&root->vm_rb);
		struct vm_area_struct *vma;
		vma = rb_entry_safe(rb_node, struct vm_area_struct, vm_rb);
		if (vma && vma->vm_flags & VM_GROWSDOWN
			&& root->max_gap == vma->rb_subtree_gap)
			goto get_free_pool;

		return root->begin;
	}

get_free_pool:
	addr = vmpool_alloc(&mm->vmpool_rb, addr, len, flag);

	return IS_ERR_VALUE(addr) ? addr : VMR_OFFSET(addr);
}

static unsigned long
address_hint(struct lego_mm_struct *mm, unsigned long addr,
	     unsigned long new_range, unsigned long flag,
	     unsigned long first_scheme_len, unsigned long scheme_count)
{
	unsigned long end;

	vma_trace("%s, new_range: %lx, addr: %lx, first_scheme_len: %lx, "
		  "flag: %lx, scheme_count: %d\n", __func__,
		  new_range, addr, first_scheme_len, flag, scheme_count);

	/* on hint for MAP_FIXED */
	if (flag & MAP_FIXED)
		return addr;

	end = min((unsigned long)(new_range + VMR_ALIGN(first_scheme_len)),
		  (unsigned long)PAGE_ALIGN(TASK_SIZE - MIN_GAP));

#ifdef CONFIG_VMA_CACHE_AWARENESS
	/* For split, always aligned to vmrange end boundary with offset */
	if (scheme_count > 1)
		return end - first_scheme_len;

	/* if user provides a hint, following the hint when it falls
	 * into desired new range */
	if (addr && vmr_idx(addr) == vmr_idx(new_range))
		return addr;

	/* for reducing the chance of virtual extended cache conflict */
	return new_range + abs(mm->addr_offset - first_scheme_len);
#else
	return end - first_scheme_len;
#endif
}

/*
 * Some cases for croping request start and len
 * Case 1: len aligned
 *	VM_GRANULARITY		0.....1.....2.....3.....4
 *	Free			      |.................|
 *	request len		      |...........|
 * Case 2: len not aligned, still within free pool
 *	VM_GRANULARITY		0.....1.....2.....3.....4
 *	Free			|.................|
 *	request len		   |..............|
 * Case 3: len not aligned, cover some already assigned
 *	   ranges, but still on the same node
 *	VM_GRANULARITY		0.....1.....2.....3.....4
 *	Free			            |...........|
 *	request len		         |....node 1....|
 *	already assigned	|..node 1...|
 * Case 4: len not aligned, cover some already assigned
 *	   ranges, and they are on different nodes
 *	VM_GRANULARITY		0.....1.....2.....3.....4
 *	Free			            |...........|
 *	request len		         |....node 2....|
 *	already assigned	|..node 1...|
 *
 * Cases for request end is mirror of cases above
 * Solution, case 1 & 2 are easy, just mapped those free range,
 * Case 3 will result a merge. Since, moving already given range
 * will result overhead, for case 4, don't follow gmm sugguestion
 * and crop request into two
 */
static unsigned long
do_dist_mmap_homenode(struct lego_mm_struct *mm, struct alloc_scheme *scheme,
	int scheme_count, unsigned long new_range, struct lego_file *file,
	unsigned long addr, unsigned long len, unsigned long prot,
	unsigned long flag, vm_flags_t vm_flags, unsigned long pgoff)
{
	struct vma_tree **map = mm->vmrange_map;
	unsigned long var_addr;
	unsigned long counter = 0, iteration_counter = 1;
	unsigned long ret;

	vma_trace("%s, new_range: %lx, addr: %lx, len: %lx, flag: %lx, "
		  "vm_flags: %lx, pgoff: %lx, scheme_count: %d\n", __func__,
		  new_range, addr, len, flag, vm_flags, pgoff, scheme_count);

	var_addr = address_hint(mm, addr, new_range,
				flag, scheme[0].len, scheme_count);

	while (counter < scheme_count) {
		struct alloc_scheme *cur_scheme = &scheme[counter];
		struct vma_tree *root;
		unsigned long cur_len = PAGE_ALIGN(cur_scheme->len);
		unsigned long idx = vmr_idx(var_addr);
		unsigned long end, end_idx, request;
		int nid = cur_scheme->nid;

		/* Case 1, 2, 3 */
		if (!map[idx] || VMR_ALIGN(var_addr) == var_addr
			      || nid == map[idx]->mnode) {
			request = cur_len;
			goto another_half;
		}
		/* Case 4 */
		request = min((unsigned long)(map[idx]->end - var_addr),
			       cur_len);
		nid = map[idx]->mnode;

another_half:
		/* deal with end */
		end = var_addr + request;
		end_idx = vmr_idx(end);
		if (map[end_idx] && (nid != map[end_idx]->mnode ||
		   (map[idx] && map[idx] != map[end_idx])))
			request -= end - VMR_OFFSET(end);

		VMA_BUG_ON(PAGE_ALIGN(len) < request);
		vma_trace("%s, addr: %lx, request: %lx, len: %lx, "
			  "scheme counter: %lx\n", __func__,
			  var_addr, request, cur_len, counter);

		/* map vmrange array */
		ret = map_vmatrees(mm, nid, var_addr, request, flag);
		if (ret)
			return ret;

		/* populate request */
		root = get_vmatree_by_addr(mm, var_addr);
		if (is_local(nid)) {
			load_vma_context(mm, root);
			ret = do_mmap(mm->task, file, var_addr, request,
				      prot, flag, vm_flags, pgoff);
			save_update_vma_context(mm, root);
			if (IS_ERR_VALUE(ret))
				return ret;
		} else {
			unsigned long reply_max_gap;

			VMA_BUG_ON(!is_homenode(mm->task));
			ret = distribute_mmap(mm->task, VMR_OFFSET(var_addr),
					      var_addr, request, prot, flag,
					      vm_flags, pgoff, nid,
					      file, &reply_max_gap);
			if (IS_ERR_VALUE(ret))
				return ret;

			root->max_gap = reply_max_gap;
		}
		sort_node_gaps(mm, root);

		/*
		 * the return addr should be the return addr
		 * of first iteration
		 */
		if (iteration_counter == 1)
			addr = ret;

		/* update variable for next round */
		cur_scheme->len -= request;
		var_addr += request;
		pgoff += request >> PAGE_SHIFT;
		if (!cur_scheme->len)
			counter++;
		iteration_counter++;

		VMA_BUG_ON(PAGE_ALIGN(request) > request);
		VMA_BUG_ON((long)(cur_scheme->len) < 0);
	}
#ifdef CONFIG_VMA_CACHE_AWARENESS
	/* update address offset with address assigned this time */
	if (!(flag & MAP_FIXED))
		mm->addr_offset = addr % VM_GRANULARITY;
#endif

	return addr;
}

unsigned long
do_dist_mmap(struct lego_mm_struct *mm, struct lego_file *file,
	     int mnode, unsigned long new_range, unsigned long addr,
	     unsigned long len, unsigned long prot, unsigned long flag,
	     vm_flags_t vm_flags, unsigned long pgoff, unsigned long *max_gap)
{
	struct vma_tree *root;
	unsigned long ret;

	vma_trace("%s, new_range: %lx, addr: %lx, len: %lx, "
		  "flag: %lx, vm_flags: %lx, pgoff: %lx\n",
		  __func__, new_range, addr, len, flag, vm_flags, pgoff);

	len = PAGE_ALIGN(len);
	if (!len)
		return -ENOMEM;

	/* offset overflow? */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
		return -EOVERFLOW;

	if (flag & MAP_FIXED)
		new_range = addr;
	ret = map_vmatrees(mm, LEGO_LOCAL_NID, new_range, len, flag);
	if (ret)
		return ret;

	root = get_vmatree_by_addr(mm, new_range);
	if (is_local(mnode)) {
		load_vma_context(mm, root);
		ret = do_mmap(mm->task, file, addr, len,
			      prot, flag, vm_flags, pgoff);
		save_update_vma_context(mm, root);
		if (IS_ERR_VALUE(ret))
			return ret;
	} else {
		unsigned long reply_max_gap;
		BUG_ON(!is_homenode(mm->task));

		ret = distribute_mmap(mm->task, new_range, addr, len,
				      prot, flag, vm_flags, pgoff, mnode,
				      file, &reply_max_gap);
		if (IS_ERR_VALUE(ret))
			return ret;

		root->max_gap = reply_max_gap;
	}
	*max_gap = root->max_gap;
	return ret;
}

unsigned long
distvm_mmap_homenode_noconsult(struct lego_mm_struct *mm,
	struct lego_file *file, unsigned long addr, unsigned long len,
	unsigned long prot, unsigned long flag, unsigned long pgoff)
{
	struct consult_reply *reply;
	struct alloc_scheme *scheme;
	int scheme_count;
	unsigned long new_range, ret;

	vma_trace("%s, addr: %lx, len: %lx, pgoff: %lx, flag: %lx\n",
			__func__, addr, len, pgoff, flag);

	len = PAGE_ALIGN(len);
	if (!len)
		return -ENOMEM;

	/* offset overflow? */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
		return -EOVERFLOW;

	reply = kmalloc(sizeof(struct consult_reply), GFP_KERNEL);
	if (!reply)
		return -ENOMEM;

	reply->count = 1;
	reply->scheme[0].nid = LEGO_LOCAL_NID;
	reply->scheme[0].len = len;

	/*
	 * search all the gaps in all node will result overhead,
	 * in this function, nid will only be used if the size can fit
	 * into one tree, therefore, just use first entry in gmm reply
	 */
	extract_reply(reply, &scheme_count, &scheme);
	new_range = get_unmapped_range(mm, addr, len, scheme[0].nid,
				       flag, scheme_count);
	if (IS_ERR_VALUE(new_range)) {
		return new_range;
	}

	ret = do_dist_mmap_homenode(mm, scheme, scheme_count, new_range,
				    file, addr, len, prot, flag, 0, pgoff);
	kfree(reply);

	vma_trace("%s, return: %lx\n", __func__, ret);
	mmap_brk_validate(mm, ret, len);
	return ret;
}

unsigned long
distvm_mmap_homenode(struct lego_mm_struct *mm, struct lego_file *file,
		     unsigned long addr, unsigned long len, unsigned long prot,
		     unsigned long flag, unsigned long pgoff)
{
	struct consult_reply *reply;
	struct alloc_scheme *scheme;
	int scheme_count;
	unsigned long new_range, ret;

	vma_trace("%s, addr: %lx, len: %lx, pgoff: %lx, flag: %lx\n",
			__func__, addr, len, pgoff, flag);

	len = PAGE_ALIGN(len);
	if (!len)
		return -ENOMEM;

	/* offset overflow? */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
		return -EOVERFLOW;

	reply = kmalloc(sizeof(struct consult_reply), GFP_KERNEL);
	if (!reply)
		return -ENOMEM;

	ret = consult_gmm(len, flag, reply);
	if (ret)
		goto out;

	/*
	 * search all the gaps in all node will result overhead,
	 * in this function, nid will only be used if the size can fit
	 * into one tree, therefore, just use first entry in gmm reply
	 */
	extract_reply(reply, &scheme_count, &scheme);
	new_range = get_unmapped_range(mm, addr, len, scheme[0].nid,
				       flag, scheme_count);
	if (IS_ERR_VALUE(new_range)) {
		ret = new_range;
		goto out;
	}

	ret = do_dist_mmap_homenode(mm, scheme, scheme_count, new_range,
				    file, addr, len, prot, flag, 0, pgoff);

out:
	kfree(reply);

	vma_trace("%s, return: %lx\n", __func__, ret);
	mmap_brk_validate(mm, ret, len);
	return ret;
}

int
distvm_brk_homenode(struct lego_mm_struct *mm,
		    unsigned long addr, unsigned long len)
{
	struct consult_reply *reply;
	struct alloc_scheme *scheme;
	int scheme_count;
	vm_flags_t vm_flags = VM_READ | VM_WRITE | mm->def_flags;
	unsigned long flag = MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS;
	unsigned long new_range, ret;

	vma_trace("%s, addr: %lx, len: %lx\n", __func__, addr, len);

	reply = kzalloc(sizeof(struct consult_reply), GFP_KERNEL);
	if (!reply)
		return -ENOMEM;

	ret = consult_gmm(len, flag, reply);
	if (ret)
		goto out;

	extract_reply(reply, &scheme_count, &scheme);
	new_range = get_unmapped_range(mm, addr, len, scheme[0].nid,
				       MAP_FIXED, scheme_count);
	if (IS_ERR_VALUE(new_range)) {
		ret = new_range;
		goto out;
	}

	ret = do_dist_mmap_homenode(mm, scheme, scheme_count, new_range,
				    NULL, addr, len, 0, flag, vm_flags, 0);

	/* success! return 0 */
	if(!IS_ERR_VALUE(ret))
		ret = 0;

out:
	kfree(reply);

	vma_trace("%s, return: %lx\n", __func__, ret);
	mmap_brk_validate(mm, addr, len);
	return ret;
}


int distvm_munmap(struct lego_mm_struct *mm, unsigned long begin,
		  unsigned long len, unsigned long *max_gap)
{
	struct vma_tree *root;
	int ret;

	vma_trace("%s, begin: %lx, len: %lx\n", __func__, begin, len);

	ret = unmap_vmatrees(mm, begin, len);
	if (ret)
		return ret;

	root = get_vmatree_by_addr(mm, begin);
	if (!root)
		*max_gap = VMR_ALIGN(begin + len) - VMR_OFFSET(begin);
	else
		*max_gap = root->max_gap;

	return 0;
}

int
distvm_munmap_homenode(struct lego_mm_struct *mm,
		       unsigned long begin, unsigned long len)
{
	int ret;

	vma_trace("%s, begin: %lx, len: %lx\n", __func__, begin, len);

	ret = unmap_vmatrees(mm, begin, len);
	update_nodegaps_freepool(mm, begin, len);

	return ret;
}

unsigned long
distvm_mremap_grow(struct lego_task_struct *tsk, unsigned long addr,
		   unsigned long old_len, unsigned long new_len)
{
	struct vm_area_struct *vma;
	struct vma_tree *root = tsk->mm->vmrange_map[vmr_idx(addr)];

	vma_trace("%s, addr: %lx, old_len: %lx, new_len: %lx\n",
		  __func__, addr, old_len, new_len);

	load_vma_context(tsk->mm, root);

	/* Ok, we need to grow.. */
	vma = vma_to_resize(addr, old_len, new_len, tsk);
	if (IS_ERR(vma))
		return PTR_ERR(vma);

	/* old_len exactly to the end of the area.. */
	if (old_len != vma->vm_end - addr)
		goto bad;

	/* new_len within range end */
	if (addr + new_len > root->end)
		goto bad;

	/* can we just expand the current mapping? */
	if (!vma_expandable(tsk, vma, new_len - old_len))
		goto bad;

	if (vma_adjust(vma, vma->vm_start, addr+new_len, vma->vm_pgoff, NULL))
		return -ENOMEM;

	save_update_vma_context(tsk->mm, root);
	return 0;

bad:
	return -EPERM;
}

unsigned long
do_dist_mremap_move(struct lego_mm_struct *mm, int mnode,
		unsigned long old_addr, unsigned long old_len,
		unsigned long new_len, unsigned long new_range,
		unsigned long *old_max_gap, unsigned long *new_max_gap)
{
	struct vma_tree *oldroot = get_vmatree_by_addr(mm, old_addr);
	struct vma_tree *newroot = get_vmatree_by_addr(mm, new_range);
	struct vm_area_struct *vma;
	unsigned long flag, new_addr;

	vma_trace("%s, mnode: %d, old_addr: %lx, old_len: %lx, "
		  "new_len: %lx, new_range: %lx\n",
		  __func__, mnode, old_addr, old_len, new_len, new_range);
	VMA_BUG_ON(!oldroot);

	if (!newroot) {
		int ret = map_vmatrees(mm, mnode, new_range, new_len, 0);
		if (ret)
			return (unsigned long)ret;

		newroot = get_vmatree_by_addr(mm, new_range);
	}

	/* remote request */
	if (!is_local(mnode)) {
		new_addr = distribute_mremap_move(mm->task, old_addr,
				old_len, new_len, new_range, oldroot->mnode,
				old_max_gap, new_max_gap);

		if (IS_ERR_VALUE(new_addr))
			goto out;

		oldroot->max_gap = *old_max_gap;
		newroot->max_gap = *new_max_gap;
		goto out;
	}

	/* local request */
	vma = find_vma(mm, old_addr);

	VMA_BUG_ON(!vma);
	VMA_BUG_ON(vma->vm_start > old_addr);

	if (vma->vm_flags & VM_MAYSHARE)
		flag = MAP_SHARED;
	else
		flag = MAP_PRIVATE;

	load_vma_context(mm, newroot);
	new_addr = get_unmapped_area(mm->task, vma->vm_file, 0, new_len,
			vma->vm_pgoff+((old_addr-vma->vm_start) >> PAGE_SHIFT),
			flag);
	if (offset_in_page(new_addr))
		return new_addr;

	/*
	 * given vma is pointing to old_addr, and context in lego_mm_struct
	 * is new_addr, we are good to call move_vma
	 */
	new_addr = move_vma(mm->task, vma, old_addr,
			    old_len, new_len, new_addr);
	save_update_vma_context(mm, newroot);
	*new_max_gap = newroot->max_gap;

	if (offset_in_page(new_addr)) {
		/* keep old mapping when move_vma failed and unmap new */
		distvm_munmap(mm, new_addr, new_len, new_max_gap);
		return new_addr;
	}
	distvm_munmap(mm, old_addr, old_len, old_max_gap);
	oldroot->max_gap = *old_max_gap;

out:
	return new_addr;
}

unsigned long
do_dist_mremap_move_split(struct lego_mm_struct *mm, unsigned long old_addr,
			  unsigned long old_len, unsigned long new_addr,
			  unsigned long new_len, unsigned long *old_max_gap,
			  unsigned long *new_max_gap)
{
	struct vma_tree *newroot = get_vmatree_by_addr(mm, new_addr);
	struct vm_area_struct *vma;

	vma_trace("%s, old_addr: %lx, old_len: %lx, "
		  "new_len: %lx, new_addr %lx\n",
		  __func__, old_addr, old_len, new_len, new_addr);

	if (!newroot) {
		int ret = map_vmatrees(mm, LEGO_LOCAL_NID,
				       new_addr, new_len, 0);
		if (ret)
			return (unsigned long)ret;

		newroot = get_vmatree_by_addr(mm, new_addr);
	}

	vma = find_vma(mm, old_addr);

	VMA_BUG_ON(!vma);
	VMA_BUG_ON(vma->vm_start > old_addr);

	load_vma_context(mm, newroot);
	new_addr = move_vma(mm->task, vma, old_addr,
			    old_len, new_len, new_addr);
	save_update_vma_context(mm, newroot);

	if (offset_in_page(new_addr)) {
		/* keep old mapping when move_vma failed and unmap new */
		distvm_munmap(mm, new_addr, new_len, new_max_gap);
		return new_addr;
	}
	distvm_munmap(mm, old_addr, old_len, old_max_gap);
	*new_max_gap = newroot->max_gap;

	return new_addr;
}

static unsigned long
do_dist_mremap_move_split_homenode(struct lego_mm_struct *mm,
		unsigned long old_addr, unsigned long old_len,
		unsigned long new_len, unsigned long new_range)
{
	struct vma_tree *root = get_vmatree_by_addr(mm, old_addr);
	unsigned long delta = 0, ret, new_addr;

	vma_trace("%s, old_addr: %lx, old_len: %lx, "
		  "new_len: %lx, new_range: %lx\n",
		  __func__, old_addr, old_len, new_len, new_range);

	/* make new_addr same offset to vm range boundary */
	new_addr = new_range + (old_addr - root->begin);

	while (delta < old_len) {
		struct vma_tree *newroot;
		unsigned long end, old_req, new_req;

		root = get_vmatree_by_addr(mm, old_addr + delta);
		end = min((unsigned long)root->end, old_addr + old_len);
		old_req = end - (old_addr + delta);
		new_req = old_req;
		if (delta + old_req == old_len)
			new_req += new_len - old_len;

		ret = map_vmatrees(mm, root->mnode,
				   new_addr + delta, new_req, 0);
		if (ret)
			break;

		newroot = get_vmatree_by_addr(mm, new_addr + delta);
		if (is_local(root->mnode)) {
			unsigned long unused1, unused2;
			ret = do_dist_mremap_move_split(mm,
					old_addr + delta, old_req,
					new_addr + delta, new_req,
					&unused1, &unused2);

			if (IS_ERR_VALUE(ret))
				break;
		} else {
			unsigned long old_max_gap, new_max_gap;
			ret = distribute_mremap_move_split(mm->task,
					old_addr + delta, old_req,
					new_addr + delta, new_req,
					root->mnode,
					&old_max_gap, &new_max_gap);

			if (IS_ERR_VALUE(ret))
				break;

			root->max_gap = old_max_gap;
			newroot->max_gap = new_max_gap;
		}
		if (IS_ERR_VALUE(ret))
			break;

		update_nodegaps_freepool(mm, old_addr + delta, old_req);
		sort_node_gaps(mm, newroot);

		delta += new_req;
	}
	return IS_ERR_VALUE(ret) ? ret : new_addr;
}

unsigned long
distvm_mremap_homenode(struct lego_mm_struct *mm, unsigned long old_addr,
		       unsigned long old_len, unsigned long new_len,
		       unsigned long flag, unsigned long new_addr)
{
	struct vma_tree *root;
	unsigned long ret, begin, new_range;
	unsigned long idx = 0, delta = 0;
	int nr_split = 0;

	vma_trace("%s, old_addr: %lx, old_len: %lx, "
		  "new_len: %lx, flag: %lx, new_addr %lx\n",
		  __func__, old_addr, old_len, new_len, flag, new_addr);

	/*
	 * TODO: current version doesn't support MREMAP_FIXED due to it's
	 * complexity and application rarely use it. need to add it after
	 * deadline, below will explain one most complex case with this flag.
	 * When fixed is specified, if new addr is offset relevant to vm range
	 * boundary is different from that of old addr, we need to choose the
	 * a mapping policy which results least data movement accross node.
	 */
	VMA_BUG_ON(flag & MREMAP_FIXED);

	if (old_len == new_len) {
		ret = old_addr;
		goto out;
	}
	/*
	 * Always allow a shrinking remap:
	 * that just unmaps the unnecessary pages..
	 */
	if (old_len > new_len) {
		ret = distvm_munmap_homenode(mm, old_addr + new_len,
					     old_len - new_len);
		if (!ret)
			ret = old_addr;
		goto out;
	}

	/* get last range within old_len */
	root = get_vmatree_by_addr(mm, old_addr + old_len);
	VMA_BUG_ON(!root);

	/* get how much to grow */
	begin = max((unsigned long)root->begin, old_addr);
	if (begin != old_addr)
		delta = begin - old_addr;

	/* try growing */
	if (is_local(root->mnode)) {
		ret = distvm_mremap_grow(mm->task, begin,
					 old_len - delta, new_len - delta);
	} else {
		unsigned long reply_max_gap;
		ret = distribute_mremap_grow(mm->task, begin,
					old_len - delta, new_len - delta,
					root->mnode, &reply_max_gap);
		if (!ret)
			root->max_gap = reply_max_gap;
	}
	if (!ret) {
		sort_node_gaps(mm, root);
		ret = old_addr;
	}

	if (ret != -EPERM || !(flag & MREMAP_MAYMOVE))
		goto out;

	/* last method to remap, create a new one and move */
	/* count nr of nodes old area across */
	do {
		struct vma_tree *pos = get_vmatree_by_addr(mm, old_addr + idx);
		idx = pos->end - old_addr;
		nr_split++;
	} while (idx + old_addr < root->end);

	root = get_vmatree_by_addr(mm, old_addr);
	if (nr_split == 1) {
		unsigned long unused1, unused2;
		new_range = get_unmapped_range(mm, 0, new_len,
					root->mnode, 0, nr_split);
		ret = do_dist_mremap_move(mm, root->mnode, old_addr,
					old_len, new_len, new_range,
					&unused1, &unused2);
		update_nodegaps_freepool(mm, old_addr, old_len);
		sort_node_gaps(mm, get_vmatree_by_addr(mm, new_range));
	} else {
		/*
		 * to result no data move across node, new_addr
		 * should have same offset to vm range boundary
		 * as old_addr, because of it. we may request more
		 * ranges than new_len
		 */
		new_range = get_unmapped_range(mm, 0,
					new_len + (old_addr - root->begin),
					root->mnode, 0, nr_split);
		ret = do_dist_mremap_move_split_homenode(mm, old_addr,
					old_len, new_len, new_range);
	}

out:
	vma_trace("%s, return: %lx\n", __func__, ret);
	return ret;
}
