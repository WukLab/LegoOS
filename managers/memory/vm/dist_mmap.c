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
 * 	    instead of calling vm range, we use vma tree
 * 
 * variable naming convention:
 * root: usually indicates the root of one vma rbtree
 * range: address aligned to VM_GRANULARIY, implicating the begin of 
 *	  vma tree and only used for constructing vma tree
 * node: one entry of node_map under lego_mm_struct, one node 
 *	 corresponding to one memory component, containing a list
 *	 of vma tree roots, sorted by gaps reversely
 */

#include <lego/slab.h>
#include <lego/list.h>
#include <lego/comp_common.h>
#include <lego/fit_ibapi.h>
#include <memory/distvm.h> 
#include <monitor/common.h>

static int vmpool_init(struct lego_mm_struct *mm)
{
	struct rb_root *root = &mm->vmpool_rb;
	struct vm_pool_struct *new;
	new = kzalloc(sizeof(struct vm_pool_struct), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

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

int distvm_init_homenode(struct lego_mm_struct *mm)
{	
	struct distvm_node **node;
	/* assign new node infos array */
	mm->node_map = kzalloc(NODEMAP_SIZE, GFP_KERNEL);
	if (unlikely(!mm->node_map))
		return -ENOMEM;

	/* initialize list for homenode */
	node = &mm->node_map[MY_NODE_ID];
	*node = kzalloc(sizeof(struct distvm_node), GFP_KERNEL);
	if (unlikely(!(*node)))
		return -ENOMEM;
	INIT_LIST_HEAD(&(*node)->list);
	
	/* initiate free pool */
	mm->vmpool_rb = RB_ROOT;
	if (vmpool_init(mm))
		return -ENOMEM;

	return distvm_init(mm);
}

void distvm_exit(struct lego_mm_struct *mm)
{
	struct vma_tree **map = mm->vmrange_map;
	int i, ret;

	for (i = 0; i < VMR_COUNT; i++) {
		struct vma_tree *root;
		u64 end, unused;
		if (!map[i])
			continue;

		root = map[i];
		i = last_vmr_idx(map[i]->end);

		end = min((u64)root->end, (u64)TASK_SIZE);
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

void dump_vmas_onetree(struct vma_tree *root)
{
#ifdef CONFIG_DEBUG_VMA
	struct vm_area_struct *pos;
	if (!root) {
		vma_debug("WARN: root given is an empty pointer\n");
		return;
	}
	pos = root->mmap;
	vma_debug("[DUMP] range begin: %lx, range end: %lx, max_gap: %Lx\n", 
				root->begin, root->end, root->max_gap);
	if (!pos) {
		vma_debug("[DUMP] No vmas in this tree\n");
		return;
	}
	for (; pos; pos = pos->vm_next) {
		vma_debug("[DUMP] start: %lx, end: %lx, "
			  "gap: %lx, vm_flags: %lx\n",
			  pos->vm_start, pos->vm_end, 
			  pos->rb_subtree_gap, pos->vm_flags);
	}
#endif
}

void dump_vmas_onenode(struct lego_mm_struct *mm)
{
#ifdef CONFIG_DEBUG_VMA
	struct vma_tree **map = mm->vmrange_map;
	u32 idx = 0;
	vma_debug("[DUMP] ************** vma print start **************\n");
	for (idx = 0; idx < VMR_COUNT; idx++) {
		struct vma_tree *root = map[idx];
		if (!root)
			continue;
		
		dump_vmas_onetree(root);
		idx = vmr_idx(VMR_ALIGN(root->end)) - 1;
	}
	vma_debug("[DUMP] ************* vma print done ****************\n");
#endif
}

void dump_gaps_onenode(struct distvm_node *node)
{
#ifdef CONFIG_DEBUG_VMA
	struct list_head *head = &node->list;
	struct vma_tree *pos;
	list_for_each_entry(pos, head, list)
		vma_debug("[GAP] max_gap: %Lx, is_fixed: %lx\n", 
			  pos->max_gap, pos->flag & MAP_FIXED);
#endif
}

void dump_reply(struct vmr_map_reply *reply)
{
#ifdef CONFIG_DEBUG_VMA
	int i;
	struct vmr_map_struct *entry;
	if (!reply) {
		vma_debug("WARN: given reply is empty, stop printing\n");
		return;
	}
	if (!reply->nr_entry)
		return;

	vma_debug("[DUMP] ************** reply print start **************\n");
	vma_debug("[DUMP] reply count: %d, max count: %d\n", 
				reply->nr_entry, MAX_VMA_REPLY_ENTRY);
	entry = reply->map;
	for (i = 0; i < reply->nr_entry; i++) {
		vma_debug("[DUMP] mnode: %d, start: %lx, len: %lx\n", 
			entry[i].mnode, entry[i].start, entry[i].len);
	}
	vma_debug("[DUMP] ************** reply print done ***************\n");
#endif
}

static inline void 
vmpool_overlap_check(u64 pstart, u64 pend, u64 start, u64 end)
{
	/* 
	 * For debug, warn if any overlap between request and
	 * already freed pool
	 * CASE 1:	|start.................end|
	 * 			|pstart...............pend|
	 *
	 * CASE 2:		|start.................end|
	 * 		|pstart...............pend|
	 */
	VMA_WARN(pstart > start && pstart < end, 
			"BUG! vm pools bug case 1 discovered\n");
	VMA_WARN(pend > start && pend < end, 
			"BUG! vm pools bug case 2 discovered\n");
}

/* retieve start and end should be VM_GRANULARITY aligned */
int vmpool_retrieve(struct rb_root *root, u64 start, u64 end)
{
	struct rb_node **node = &(root->rb_node), *parent = NULL;
	struct vm_pool_struct *new;

	vma_debug("%s, start: %Lx, end: %Lx\n", __func__, start, end);

	/* TASK_SIZE is not vm range aligned */
	if (end == TASK_SIZE)
		end = VMR_ALIGN(end);
	if (VMR_ALIGN(start) > start || VMR_ALIGN(end) > end)
		return -EINVAL; 

	while(*node) {
		struct rb_node *adj;
		struct vm_pool_struct *pool, *adj_pool = NULL;
		pool = rb_entry(*node, struct vm_pool_struct, vmr_rb);

		vmpool_overlap_check(pool->pool_start, pool->pool_end, start, end);
		
		/* Good cases, don't even need to create a new tree node,
		 * and potentially remove tree node
		 * CASE 1: 	|start.......end|
		 * 				|pstart.....pend|
		 *
		 * CASE 2: 			|start.......end|
		 * 		|pstart.....pend|
		 */
		if (pool->pool_start == end) {
			pool->pool_start = start;

			/* check potential merge */
			adj = rb_prev(*node);
			/* currect pool is the lowest pool */
			if (!adj)
				return 0;
			
			adj_pool = rb_entry(adj, struct vm_pool_struct, vmr_rb);
			/* start not connected with end of previous hole */
			if (adj_pool->pool_end < start)
				return 0;

			/* finally, good case 1 */
			pool->pool_start = adj_pool->pool_start;
			rb_erase(adj, root);
			kfree(adj_pool);
			adj_pool = NULL;
			return 0;
		} else if (pool->pool_end == start) {
			/* mirror of above */
			pool->pool_end = end;

			adj = rb_next(*node);
			if (!adj)
				return 0;
				
			adj_pool = rb_entry(adj, struct vm_pool_struct, vmr_rb);
			/* start not connected with end of next hole */
			if (adj_pool->pool_start > end)
				return 0;

			/* finally, good case 2 */
			pool->pool_end = adj_pool->pool_end;
			rb_erase(adj, root);
			kfree(adj_pool);
			adj_pool = NULL;
			return 0;
		} else {
			/* when request not adjacent to current pool, need search
		 	 * CASE 1: 	|start.......end|
		 	 * 					|pstart.....pend|
		 	 *
		 	 * CASE 2: 				|start.......end|
		 	 * 		|pstart.....pend|
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
static struct vm_pool_struct *vmpool_find(struct rb_root *root, u64 addr)
{
	struct rb_node *node = root->rb_node;
	struct vm_pool_struct *pool;

	vma_debug("%s, addr: %Lx\n", __func__, addr);
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
 * 		Request		|...........|
 * 		Final Free		    |.......|
 *
 * Case 2:	Free		|...........|
 * 		Request			|...........|
 * 		Final Free	|.......|
 *
 * Case 3:	Free		    |...........|
 * 		Request		|...................|
 * 		Final Free	Nothing, struct free
 *
 * Case 4:	Free		|...................|
 * 		Request		      |.......|
 * 		Final Free	|.....|       |.....|
 */
u64 vmpool_alloc(struct rb_root *root, u64 addr, u64 len, u64 flag)
{
	struct vm_pool_struct *pool = NULL;
	struct rb_node *node;
	u64 end = VMR_ALIGN(addr + len), cropped_start;
	u64 begin = VMR_OFFSET(addr); 
	len = end - begin;
	
	vma_debug("%s, addr: %Lx, len: %Lx, flag: %Lx\n",
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
			return addr;

		/* allocate from higher address */
		pool->pool_end -= len;
		addr = pool->pool_end;
		if (pool->pool_end == pool->pool_start) {
			rb_erase(&pool->vmr_rb, root);
			kfree(pool);
			pool = NULL;
		}
		return addr;
	}

	/* when address is specified */
	pool = vmpool_find(root, begin);
	if (!pool)
		return addr;
	cropped_start = max((u64)pool->pool_start, (u64)addr);
	while (cropped_start < end) {
		struct rb_node *next;
		if (cropped_start == pool->pool_start) {
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
				pool = NULL;
				return addr;
			}
			kfree(pool);
			pool = NULL;
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
			pool->pool_end = cropped_start;
		
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
			pool->pool_end = cropped_start;
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
		cropped_start = pool->pool_start;
	}
	return addr;
}

static u64
distribute_mmap(struct lego_task_struct *tsk, u64 new_range, u64 addr, 
		u64 len, u64 prot, u64 flags, vm_flags_t vm_flags, u64 pgoff, 
		u64 mnode, struct lego_file *file, u64 *max_gap)
{			
	u64 ret;
	struct m2m_mmap_struct info;
	struct m2m_mmap_reply_struct reply;

	info.pid = tsk->pid;
	info.new_range = new_range;
	info.addr = addr;
	info.len = len;
	info.prot = prot;
	info.flags = flags;
	info.vm_flags = vm_flags;
	info.pgoff = pgoff;
	memcpy(&info.f_name, &file->filename, MAX_FILENAME_LENGTH);

	ret = net_send_reply_timeout(mnode, M2M_MMAP, (void *)&info, 
			sizeof(struct m2m_mmap_struct), (void *)&reply, 
			sizeof(struct m2m_mmap_reply_struct), 
			false, FIT_MAX_TIMEOUT_SEC);
	
	if (ret)
		return ret;

	*max_gap = reply.max_gap;
	return reply.addr;
}

static int 
distribute_munmap(struct lego_task_struct *tsk, __u64 begin, 
		  __u64 len, __u64 mnode, __u64 *max_gap)
{
	int ret;
	struct m2m_munmap_struct info;
	struct m2m_munmap_reply_struct reply;

	info.pid = tsk->pid;
	info.begin = begin;
	info.len = len;

	ret = net_send_reply_timeout(mnode, M2M_MUNMAP, (void *)&info, 
			sizeof(struct m2m_munmap_struct), (void *)&reply, 
			sizeof(struct m2m_munmap_reply_struct), 
			false, FIT_MAX_TIMEOUT_SEC);

	if (ret)
		return ret;

	*max_gap = reply.max_gap;
	return reply.status;
}

static int 
distribute_mremap_grow(struct lego_task_struct *tsk, __u64 addr, 
		       __u64 old_len, __u64 new_len, __u64 mnode, 
		       __u64 *max_gap)
{
	int ret;
	struct m2m_mremap_grow_struct info;
	struct m2m_mremap_grow_reply_struct reply;

	info.pid = tsk->pid;
	info.addr = addr;
	info.old_len = old_len;
	info.new_len = new_len;

	ret = net_send_reply_timeout(mnode, M2M_MREMAP_GROW, (void *)&info, 
			sizeof(struct m2m_mremap_grow_struct), (void *)&reply, 
			sizeof(struct m2m_mremap_grow_reply_struct), false,
			FIT_MAX_TIMEOUT_SEC);

	if (ret)
		return ret;

	*max_gap = reply.max_gap;
	return reply.status;
}

static int 
distribute_mremap_move(struct lego_task_struct *tsk, __u64 old_addr, 
		       __u64 old_len, __u64 new_len, __u64 new_range,
		       __u64 mnode, __u64 *old_max_gap, __u64 *new_max_gap)
{
	int ret;
	struct m2m_mremap_move_struct info;
	struct m2m_mremap_move_reply_struct reply;

	info.pid = tsk->pid;
	info.old_addr = old_addr;
	info.old_len = old_len;
	info.new_len = new_len;
	info.new_range = new_range;

	ret = net_send_reply_timeout(mnode, M2M_MREMAP_MOVE, (void *)&info, 
			sizeof(struct m2m_mremap_move_struct), (void *)&reply, 
			sizeof(struct m2m_mremap_move_reply_struct), false,
			FIT_MAX_TIMEOUT_SEC);

	if (ret)
		return ret;

	*old_max_gap = reply.old_max_gap;
	*new_max_gap = reply.new_max_gap;
	return reply.new_addr;
}

static int 
distribute_mremap_move_split(struct lego_task_struct *tsk, __u64 old_addr, 
		       __u64 old_len, __u64 new_addr, __u64 new_len, 
		       __u64 mnode, __u64 *old_max_gap, __u64 *new_max_gap)
{
	int ret;
	struct m2m_mremap_move_split_struct info;
	struct m2m_mremap_move_split_reply_struct reply;

	info.pid = tsk->pid;
	info.old_addr = old_addr;
	info.new_addr = new_addr;
	info.old_len = old_len;
	info.new_len = new_len;

	ret = net_send_reply_timeout(mnode, M2M_MREMAP_MOVE, (void *)&info, 
		sizeof(struct m2m_mremap_move_split_struct), (void *)&reply, 
		sizeof(struct m2m_mremap_move_split_reply_struct), false,
		FIT_MAX_TIMEOUT_SEC);

	if (ret)
		return ret;

	*old_max_gap = reply.old_max_gap;
	*new_max_gap = reply.new_max_gap;
	return reply.new_addr;
}

static int 
distribute_findvma(struct lego_task_struct *tsk, __u64 begin, 
		   __u64 end, __u64 mnode)
{
	int ret;
	struct m2m_findvma_struct info;
	struct m2m_findvma_reply_struct reply;

	info.pid = tsk->pid;
	info.begin = begin;
	info.end = end;

	ret = net_send_reply_timeout(mnode, M2M_FINDVMA, (void *)&info, 
			sizeof(struct m2m_findvma_struct), (void *)&reply, 
			sizeof(struct m2m_findvma_reply_struct), 
			false, FIT_MAX_TIMEOUT_SEC);

	if (ret)
		return ret;

	return reply.vma_exist;
}

static unsigned long
extract_reply(void *replybuf, __u32 *nodecount, struct alloc_scheme **scheme)
{
	__u32 length;
	struct common_header *hdr;
	struct consult_reply *reply;

	hdr = replybuf;
	reply = consult_reply_entry(replybuf);
	*scheme = alloc_scheme_entry(replybuf);
	length = alloc_scheme_msg_size(replybuf);
	*nodecount = reply->count;

	/* received info is not corresponding to protocol */
	if (!is_reply_valid(length, reply->count))
		return -EPROTO;

	return 0;
}

static u64 consult_gmm(u64 request, void *replybuf)
{
	u64 ret = 0;

#ifdef CONFIG_GMM
	u64 gmm_node = 0;
	struct consult_info send;

	send.len = request;

	ret = net_send_reply_timeout(CONFIG_GMM_NODEID, M2MM_CONSULT, 
				&send, sizeof(struct consult_info), 
				replybuf, MAX_RXBUF_SIZE, 
				false, FIT_MAX_TIMEOUT_SEC);

#else
	/* fake reply, this mainly used for testing */
	struct common_header *hdr = replybuf;
	struct consult_reply *reply = consult_reply_entry(replybuf);
	struct alloc_scheme *node = alloc_scheme_entry(replybuf);

	hdr->length = sizeof(struct common_header) + 
		      sizeof(struct consult_reply) + 
		      sizeof(struct alloc_scheme);

	hdr->src_nid = MY_NODE_ID;
	reply->count = 1;
	node->nid = MY_NODE_ID;
	node->len = request;
#endif

	return ret;
}

/* return value: 0, no intersect. 1 intersect, other value is an error */
bool find_dist_vma_intersection(struct lego_mm_struct *mm, u64 begin, u64 end)
{
	struct vma_tree **map = mm->vmrange_map;
	struct vma_tree *root;
	u64 begin_idx = vmr_idx(begin);
	u64 end_idx = vmr_idx(VMR_ALIGN(end));
	u64 cur, prev, idx;
	bool ret = 0;

	vma_debug("%s, begin: %Lx, end: %Lx\n", __func__, begin, end);

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
	root = map[last_vmr_idx(end)];
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
	else
		root->max_gap = max((s64)(root->end - lastvma->vm_end), 
				    (s64)vma->rb_subtree_gap);
}

void sort_node_gaps(struct lego_mm_struct *mm, struct vma_tree *root)
{
	struct distvm_node *node = mm->node_map[root->mnode];
	struct list_head *head = node->list.prev;
	struct vma_tree *pos;

	list_del_init(&root->list);
	list_for_each_entry(pos, &node->list, list) {
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
	struct vmr_map_struct *entry = NULL;
	VMA_BUG_ON(!RB_EMPTY_ROOT(&root->vm_rb));
	VMA_BUG_ON(root->mmap);

	set_vmrange_map(mm, root->begin, root->end - root->begin, NULL);
	entry = get_available_reply_entry(mm);
	entry->mnode = (vmr16)MY_NODE_ID;
	entry->start = root->begin;
	entry->len = root->end - root->begin;

	if (!list_empty(&root->list))
		list_del(&root->list);
	kfree(root);
}
	
static int unmap_vmatrees(struct lego_mm_struct *mm, u64 begin, u64 len)
{
	struct vma_tree **map = mm->vmrange_map;
	u64 end = begin + len;
	u32 index = vmr_idx(begin);
	int ret;

	vma_debug("%s, begin: %Lx, len: %Lx\n", __func__, begin, len);
	/* 
	 * look up all the vma_tree in between begin and
	 * begin + len
	 */
	while (index < vmr_idx(VMR_ALIGN(end))) {
		struct vma_tree *root = map[index];
		u64 cropped_begin, cropped_end;
		
		if (!root) {
			index++;
			continue;
		}

		cropped_begin = max((u64)root->begin, (u64)begin);
		cropped_end = min((u64)root->end, (u64)end);
		index = vmr_idx(VMR_ALIGN(cropped_end));
		
		root = map[vmr_idx(cropped_begin)];
		if (is_local(root->mnode)) {
			struct vm_area_struct *vma;

			vma = find_vma(mm, cropped_begin);
			if (!vma || cropped_end <= vma->vm_start)
				continue;

			load_vma_context(mm, root);
			ret = do_munmap(mm, cropped_begin, 
					cropped_end - cropped_begin);
			save_update_vma_context(mm, root);
			if (ret)
				return ret;
		} else {
			u64 reply_max_gap;
			VMA_BUG_ON(!is_homenode(mm->task));

			ret = distribute_munmap(mm->task, begin, end - begin, 
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

u64 
map_vmatrees(struct lego_mm_struct *mm, u64 mnode, u64 addr, u64 len, u32 flag)
{
	struct vma_tree **map = mm->vmrange_map;
	struct vma_tree *root;
	struct vmr_map_struct *entry = NULL;
	u64 begin = VMR_OFFSET(addr);
	u64 end = VMR_ALIGN(addr + len); /* an exclusive boundary */
	u64 idx = vmr_idx(begin);
	u64 end_idx = vmr_idx(end);
	u64 ret;

	vma_debug("%s, addr: %Lx, len: %Lx, mnode: %Lx, flag: %x\n", 
			__func__, addr, len, mnode, flag);

	/* overlap */
	if (flag & MAP_FIXED) {
		ret = unmap_vmatrees(mm, addr, len);
		if (ret)
			return ret;
	}

	/* 
	 * since addr and len may not be VM_GRANULARITY aligned
	 * it's possible that first covered range and last covered
	 * range is not totally unmapped, thus, no action for
	 * these two ranges
	 */
	if (map[idx]) {
		begin += VM_GRANULARITY;
		idx = vmr_idx(begin);
	}
	if (map[end_idx]) {
		end -= VM_GRANULARITY;
		end_idx = vmr_idx(end);
	}
	if (end_idx - idx <= 0)
		return 0;

	/* 
	 * check if possible to merge existing tree 
	 * only merge with larger address, merge to both will
	 * possibly result overhead
	 */
	if (end_idx < VMR_COUNT && map[end_idx] && 
		      map[end_idx]->mnode == mnode) {
		root = map[end_idx];
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

	root = kmalloc(sizeof(struct vma_tree), GFP_KERNEL);
	if (!root)
		return -ENOMEM;
	
	root->vm_rb = RB_ROOT;
	root->mmap = NULL;
	root->begin = begin;
	root->end = min((u64)end, (u64)PAGE_ALIGN(TASK_SIZE - MIN_GAP));
	root->flag = flag & MAP_FIXED;
	root->max_gap = root->end - root->begin;
	root->mnode = mnode;
	INIT_LIST_HEAD(&root->list);
	
map_new_addr:
	set_vmrange_map(mm, begin, end - begin, root);
	entry = get_available_reply_entry(mm);
	entry->mnode = (vmr16)root->mnode;
	entry->start = begin;
	entry->len = end - begin;

	vma_debug("%s, begin: %Lx, len: %Lx, root: %p, map[%Lx]: %p\n", 
				__func__, begin, end - begin, root, 
				vmr_idx(begin), map[vmr_idx(begin)]);
	return 0;
}

static void 
update_nodegaps_freepool(struct lego_mm_struct *mm, u64 begin, u64 len)
{
	struct vma_tree **map = mm->vmrange_map;
	u64 end = begin + len;
	u32 index = vmr_idx(begin);

	vma_debug("%s, begin: %Lx, len: %Lx\n", __func__, begin, len);

	while (index < vmr_idx(VMR_ALIGN(end))) {
		struct vma_tree *root = map[index];
		u64 free_begin;
		u64 free_end;

		if (!root) {
			index++;
			continue;
		}

		index = vmr_idx(VMR_ALIGN(min((u64)root->end, (u64)end)));
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
 * mnode is useful only when givn address and len falls 
 * into one continous range in one node, no effect across
 * multiple nodes since it's used for search max gap. 
 * Therefore, mnode should only be where 'addr' is at
 *
 * return addr only used for map range to tree
 */
static u64 
get_unmapped_range(struct lego_mm_struct *mm, u64 addr, 
		   u64 len, u64 mnode, u64 flag, u32 nr_split)
{
	struct distvm_node **node = &mm->node_map[mnode];
	struct vma_tree *pos, *root = NULL;

	vma_debug("%s, addr: %Lx, len: %Lx, mnode: %Lx, "
		  "flag: %Lx, nr_split: %x\n", 
		  __func__, addr, len, mnode, flag, nr_split);

	if (!is_node_valid(mnode)) {
		vma_debug("memory node invalid, GMM didn't"
			  "provide a correct value\n");
		/* TODO: Current set to BUG, later, we can 
		 * change it by ignoring the request */
		BUG();
	}

	if (!(*node)) {
		*node = kzalloc(sizeof(struct distvm_node), GFP_KERNEL);
		INIT_LIST_HEAD(&(*node)->list);
	}

	if (flag & MAP_FIXED || nr_split > 1)
		goto get_free_pool;

	/* requesting a specific address */
	if (addr) {
		root = mm->vmrange_map[vmr_idx(addr)];

		/* 
		 * only follow address if it's same as 
		 * gmm suggested memory node 
		 */
		if (root && root->mnode != mnode)
			goto find_vm_range;

		/* find out if there are existing vma overlapped */
		if (TASK_SIZE - len >= addr && 
		    !find_dist_vma_intersection(mm, addr, addr + len))
			goto get_free_pool;
	}

find_vm_range:
	/* 
	 * check if there's still free space within given vm range 
	 * list is sorted by gaps in reversed order 
	 */
	dump_gaps_onenode(mm->node_map[mnode]);
	list_for_each_entry(pos, &(*node)->list, list) {
		if (pos->flag & MAP_FIXED)
			continue;
		if (pos->max_gap >= len)
			root = pos;
		if (pos->max_gap < len)
			break;
	}
	if (root)
		return root->begin;

get_free_pool:
	addr = vmpool_alloc(&mm->vmpool_rb, addr, len, flag);
	return VMR_OFFSET(addr);
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
 * 	   ranges, but still on the same node
 *	VM_GRANULARITY		0.....1.....2.....3.....4
 *	Free			            |...........|
 *	request len		         |....node 1....|
 *	already assigned 	|..node 1...|
 * Case 4: len not aligned, cover some already assigned 
 * 	   ranges, and they are on different nodes
 *	VM_GRANULARITY		0.....1.....2.....3.....4
 *	Free			            |...........|
 *	request len		         |....node 2....|
 *	already assigned 	|..node 1...|
 *
 * Cases for request end is mirror of cases above
 * Solution, case 1 & 2 are easy, just mapped those free range,
 * Case 3 will result a merge. Since, moving already given range
 * will result overhead, for case 4, don't follow gmm sugguestion
 * and crop request into two
 */
static u64 
do_dist_mmap_split(struct lego_mm_struct *mm, struct alloc_scheme *scheme,
		   u32 scheme_count, u64 new_range, struct lego_file *file, 
		   u64 addr, u64 len, u64 prot, u64 flag, 
		   vm_flags_t vm_flags, u64 pgoff)
{
	struct vma_tree **map = mm->vmrange_map;
	u64 var_addr;
	u64 counter = 0;
	u64 request = 0;
	s64 ret = 0;

	vma_debug("%s, new_range: %Lx, addr: %Lx, len: %Lx, "
		  "flag: %Lx, vm_flags: %lx, pgoff: %Lx\n", 
		  __func__, new_range, addr, len, flag, vm_flags, pgoff);

	/* 
	 * when request is splited and not MAP_FIXED, make first
	 * request len align to end of vm range
	 */
	if (!(flag & MAP_FIXED)) {
		addr = new_range + VMR_ALIGN(scheme[0].len) -
		       scheme[0].len;
	}
	var_addr = addr;

	while (counter < scheme_count) {
		struct alloc_scheme *cur_scheme = &scheme[counter];
		struct vma_tree *root;
		u64 cur_len = PAGE_ALIGN(cur_scheme->len);
		u64 cur_nid = cur_scheme->nid;
		u64 idx = vmr_idx(var_addr);
		u64 end, end_idx;

		/* Case 1, 2, 3 */
		if (!map[idx] || VMR_ALIGN(var_addr) == var_addr 
			      || cur_nid == map[idx]->mnode) {
			request = cur_len;
			goto another_half;
		}
		/* Case 4 */
		request = min((u64)cur_len, (u64)(map[idx]->end - var_addr));

another_half:
		/* deal with end */
		end = var_addr + request;
		end_idx = vmr_idx(end);
		if (map[end_idx] && cur_nid != map[end_idx]->mnode)
			request -= end - VMR_OFFSET(end);

		VMA_BUG_ON(PAGE_ALIGN(len) < request);

		/* map vmrange array */
		ret = map_vmatrees(mm, cur_nid, var_addr, request, flag);
		if (ret)
			return ret;
		
		/* populate request */
		root = map[vmr_idx(var_addr)];
		if (is_local(cur_nid)) {
			load_vma_context(mm, root);
			ret = do_mmap(mm->task, file, var_addr, request, 
						prot, flag, vm_flags, pgoff);
			save_update_vma_context(mm, root);
			if (IS_ERR_VALUE(ret))
				return ret;
		} else {
			u64 reply_max_gap;
			ret = distribute_mmap(mm->task, VMR_OFFSET(var_addr),
					var_addr, request, prot, flag, 
					vm_flags, pgoff, cur_nid, 
					file, &reply_max_gap);
			if (IS_ERR_VALUE(ret))
				return ret;

			root->max_gap = reply_max_gap;
		}
		sort_node_gaps(mm, root);

		/* update variable for next round */
		VMA_BUG_ON(PAGE_ALIGN(request) > request);
		cur_scheme->len -= request;
		VMA_BUG_ON((s64)(cur_scheme->len) < 0);
		var_addr += request;
		pgoff += request >> PAGE_SHIFT;
		if (!cur_scheme->len)
			counter++;
	}
	return addr;
}

u64 
do_dist_mmap(struct lego_mm_struct *mm, struct lego_file *file,
	     u64 mnode, u64 new_range, u64 addr, u64 len, u64 prot, 
	     u64 flag, vm_flags_t vm_flags, u64 pgoff, u64 *max_gap)
{
	struct vma_tree **map = mm->vmrange_map;
	struct vma_tree *root;
	s64 ret;

	vma_debug("%s, new_range: %Lx, addr: %Lx, len: %Lx, "
		  "flag: %Lx, vm_flags: %lx, pgoff: %Lx\n", 
		  __func__, new_range, addr, len, flag, vm_flags, pgoff);

	len = PAGE_ALIGN(len);
	if (!len)
		return -ENOMEM;

	/* offset overflow? */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
		return -EOVERFLOW;

	if (flag & MAP_FIXED)
		new_range = addr;
	ret = map_vmatrees(mm, MY_NODE_ID, new_range, len, flag);
	if (ret)
		return ret;

	root = map[vmr_idx(new_range)];
	if (is_local(mnode)) {
		load_vma_context(mm, root);
		ret = do_mmap(mm->task, file, addr, len, 
					prot, flag, vm_flags, pgoff);
		save_update_vma_context(mm, root);
		if (IS_ERR_VALUE(ret))
			return ret;
	} else {
		u64 reply_max_gap;
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

u64 distvm_mmap_homenode(struct lego_mm_struct *mm, struct lego_file *file, 
			 u64 addr, u64 len, u64 prot, u64 flag, u64 pgoff)
{
	__u32 scheme_count;
	u64 new_range;
	unsigned long ret;
	void *replybuf;
	struct alloc_scheme *scheme;

	vma_debug("%s, addr: %Lx, len: %Lx, pgoff: %Lx, flag: %Lx\n", 
			__func__, addr, len, pgoff, flag);

	len = PAGE_ALIGN(len);
	if (!len)
		return -ENOMEM;

	/* offset overflow? */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
		return -EOVERFLOW;


	replybuf = kmalloc(MAX_RXBUF_SIZE, GFP_KERNEL);	
	if (!replybuf)
		return -ENOMEM;

	ret = consult_gmm(len, replybuf);
	if (ret) 
		goto out;

	ret = extract_reply(replybuf, &scheme_count, &scheme);
	if (ret)
		goto out;

	/* 
	 * search all the gaps in all node will result overhead,
	 * in this function, nid will only be used if the size can fit
	 * into one tree, therefore, just use first entry in gmm reply
	 */
	new_range = get_unmapped_range(mm, addr, len, scheme[0].nid, 
					 flag, scheme_count);
	if (scheme_count == 1) {
		u64 unused;
		ret = do_dist_mmap(mm, file, scheme[0].nid, 
				   new_range, addr, len, prot, 
	     			   flag, 0, pgoff, &unused);

		sort_node_gaps(mm, mm->vmrange_map[vmr_idx(new_range)]);
	} else {
		ret = do_dist_mmap_split(mm, scheme, scheme_count, 
					 new_range, file, addr, len, 
					 prot, flag, 0, pgoff);
	}

out:
	kfree(replybuf);
	vma_debug("%s, return: %lx\n", __func__, ret);
	dump_vmas_onenode(mm);
	return ret;
}

u64 distvm_brk_homenode(struct lego_mm_struct *mm, u64 addr, u64 len)
{
	__u32 scheme_count;
	u64 ret, new_range;
	u64 flag = MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS;
	vm_flags_t vm_flags = VM_READ | VM_WRITE | mm->def_flags;
	void *replybuf;
	struct alloc_scheme *scheme;

	vma_debug("%s, addr: %Lx, len: %Lx\n", __func__, addr, len);

	replybuf = kmalloc(MAX_RXBUF_SIZE, GFP_KERNEL);	
	if (!replybuf)
		return -ENOMEM;

	ret = consult_gmm(len, replybuf);
	if (ret) 
		goto out;

	ret = extract_reply(replybuf, &scheme_count, &scheme);
	if (ret)
		goto out;

	new_range = get_unmapped_range(mm, addr, len, scheme[0].nid, 
					 MAP_FIXED, scheme_count);
	if (scheme_count == 1) {
		u64 unused;
		ret = do_dist_mmap(mm, NULL, scheme[0].nid, new_range, 
				addr, len, 0, flag, vm_flags, 0, &unused);
	} else {
		ret = do_dist_mmap_split(mm, scheme, scheme_count, 
					 new_range, NULL, addr, len, 
					 0, flag, vm_flags, 0);
	}

	/* success! return 0 */
	if(!IS_ERR_VALUE(ret))
		ret = 0;

out:
	kfree(replybuf);
	vma_debug("%s, return: %Lx\n", __func__, ret);
	dump_vmas_onenode(mm);
	return ret;
}


int distvm_munmap(struct lego_mm_struct *mm, u64 begin, u64 len, u64 *max_gap)
{
	struct vma_tree **map = mm->vmrange_map;
	struct vma_tree *root;
	int ret;

	vma_debug("%s, begin: %Lx, len: %Lx\n", __func__, begin, len);
	ret = unmap_vmatrees(mm, begin, len);
	if (ret)
		return ret;

	root = map[vmr_idx(begin)];
	if (!root)
		*max_gap = VMR_ALIGN(begin + len) - VMR_OFFSET(begin);
	else
		*max_gap = root->max_gap;

	dump_vmas_onenode(mm);
	return 0;
}

int distvm_munmap_homenode(struct lego_mm_struct *mm, u64 begin, u64 len)
{
	int ret;
	vma_debug("%s, begin: %Lx, len: %Lx\n", __func__, begin, len);
	ret = unmap_vmatrees(mm, begin, len);
	update_nodegaps_freepool(mm, begin, len);
	dump_vmas_onenode(mm);
	return ret;
}

u64 distvm_mremap_grow(struct lego_task_struct *tsk, 
		       u64 addr, u64 old_len, u64 new_len)
{
	struct vm_area_struct *vma;
	struct vma_tree *root = tsk->mm->vmrange_map[vmr_idx(addr)];

	vma_debug("%s, addr: %Lx, old_len: %Lx, new_len: %Lx\n", 
			__func__, addr, old_len, new_len);

	load_vma_context(tsk->mm, root);

	/* Ok, we need to grow.. */
	vma = vma_to_resize(addr, old_len, new_len, tsk);
	if (IS_ERR(vma))
		return PTR_ERR(vma);
	
	/* old_len exactly to the end of the area.. */
	if (old_len != vma->vm_end - addr)
		goto bad;

	/* can we just expand the current mapping? */
	if (!vma_expandable(tsk, vma, new_len - old_len))
		goto bad;
	
	if (vma_adjust(vma, vma->vm_start, addr + new_len,
					vma->vm_pgoff, NULL))
		return -ENOMEM;
	
	save_update_vma_context(tsk->mm, root);
	return 0;
bad:
	return -EPERM;
}

u64 do_dist_mremap_move(struct lego_mm_struct *mm, u64 mnode, 
		u64 old_addr, u64 old_len, u64 new_len, u64 new_range, 
		u64 *old_max_gap, u64 *new_max_gap)
{
	struct vma_tree **map = mm->vmrange_map;
	struct vma_tree *oldroot, *newroot = NULL; 
	struct vm_area_struct *vma;
	u64 flag, new_addr, ret;
	
	vma_debug("%s, mnode: %Lx, old_addr: %Lx, old_len: %Lx, "
		  "new_len: %Lx, new_range: %Lx\n", 
		  __func__, mnode, old_addr, old_len, new_len, new_range);

	oldroot = map[vmr_idx(old_addr)];
	VMA_BUG_ON(!oldroot);

	newroot = map[vmr_idx(new_range)];
	if (!newroot) {
		ret = map_vmatrees(mm, MY_NODE_ID, new_range, new_len, 0);
		if (ret)
			return ret;

		newroot = map[vmr_idx(new_addr)];
	}

	/* remote request */
	if (!is_local(mnode)) {
		new_addr = distribute_mremap_move(mm->task, old_addr, 
				old_len, new_len, new_range, oldroot->mnode, 
				old_max_gap, new_max_gap);

		if (new_addr)
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
				    vma->vm_pgoff + 
				    ((old_addr - vma->vm_start) >> PAGE_SHIFT),
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

u64 do_dist_mremap_move_split(struct lego_mm_struct *mm, u64 old_addr, 
			  u64 old_len, u64 new_addr, u64 new_len, 
			  u64 *old_max_gap, u64 *new_max_gap)
{
	struct vma_tree **map = mm->vmrange_map;
	struct vma_tree *oldroot, *newroot; 
	struct vm_area_struct *vma;
	
	vma_debug("%s, old_addr: %Lx, old_len: %Lx, "
		  "new_len: %Lx, new_addr %Lx\n", 
		  __func__, old_addr, old_len, new_len, new_addr);

	oldroot = map[vmr_idx(old_addr)];
	newroot = map[vmr_idx(new_addr)];
	VMA_BUG_ON(!oldroot);
	VMA_BUG_ON(!newroot);

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

static u64 
do_dist_mremap_move_split_homenode(struct lego_mm_struct *mm, u64 old_addr, 
			u64 old_len, u64 new_len, u64 new_range)
{
	struct vma_tree **map = mm->vmrange_map;
	struct vma_tree *root = map[vmr_idx(old_addr)];
	struct vma_tree *newroot;
	u64 delta = 0, ret, new_addr;

	vma_debug("%s, old_addr: %Lx, old_len: %Lx, "
		  "new_len: %Lx, new_range: %Lx\n", 
		  __func__, old_addr, old_len, new_len, new_range);

	/* make new_addr same offset to vm range boundary */
	new_addr = new_range + (old_addr - root->begin);

	while (delta < old_len) {
		u64 end, old_req, new_req;

		root = map[vmr_idx(old_addr + delta)];
		end = min((u64)root->end, (u64)(old_addr + old_len));
		old_req = end - (old_addr + delta);
		new_req = old_req;
		if (delta + old_req == old_len)
			new_req += new_len - old_len;

vma_debug("%s, old_req: %Lx, new_req: %Lx\n", __func__, old_req, new_req);
		newroot = map[vmr_idx(new_addr + delta)];
		ret = map_vmatrees(mm, root->mnode, new_addr + delta, 
				   new_req, 0);
		if (ret)
			break;

		if (is_local(root->mnode)) {
			u64 unused1, unused2;
			ret = do_dist_mremap_move_split(mm, 
					old_addr + delta, old_req,
			  		new_addr + delta, new_req, 
			  		&unused1, &unused2);
			
			if (IS_ERR_VALUE(ret))
				break;
		} else {
			u64 old_max_gap, new_max_gap;
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
	return ret ? ret : new_addr;
}

u64 distvm_mremap_homenode(struct lego_mm_struct *mm, u64 old_addr, 
			   u64 old_len, u64 new_len, u64 flag, u64 new_addr)
{
	struct vma_tree **map = mm->vmrange_map;
	struct vma_tree *root;
	u64 ret, begin, new_range;
	u64 nr_split = 0, idx = 0, delta = 0;
	u64 unused1, unused2;

	vma_debug("%s, old_addr: %Lx, old_len: %Lx, "
		  "new_len: %Lx, flag: %Lx, new_addr %Lx\n", 
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
		ret = distvm_munmap_homenode(mm, new_addr + new_len, 
					     old_len - new_len);
		if (!ret)
			ret = old_addr;
		goto out;
	}

	/* get last range within old_len */
	root = map[vmr_idx(old_addr + old_len)];
	VMA_BUG_ON(!root);

	/* get how much to grow */
	begin = max((u64)root->begin, (u64)old_addr);
	if (begin != old_addr)
		delta = begin - old_addr;

	/* try growing */
	if (is_local(root->mnode)) {
		ret = distvm_mremap_grow(mm->task, begin, 
					 old_len - delta, new_len - delta);
	} else {
		u64 reply_max_gap;
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

	if (ret != -EPERM && !(flag & MREMAP_MAYMOVE))
		goto out;

	/* last method to remap, create a new one and move */
	/* count nr of nodes old area across */
	do {
		struct vma_tree *pos = map[vmr_idx(old_addr + idx)];
		idx = pos->end - old_addr;
		nr_split++;
	} while (idx + old_addr < root->end);

	root = map[vmr_idx(old_addr)];
	if (nr_split == 1) {
		new_range = get_unmapped_range(mm, 0, new_len, 
					root->mnode, 0, nr_split);
		new_addr = do_dist_mremap_move(mm, root->mnode, old_addr, 
					old_len, new_len, new_range, 
					&unused1, &unused2);
		update_nodegaps_freepool(mm, old_addr, old_len);
		sort_node_gaps(mm, map[vmr_idx(new_range)]);
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
		new_addr = do_dist_mremap_move_split_homenode(mm, old_addr, 
					new_addr, new_len, new_range);
	}
out:
	dump_vmas_onenode(mm);
	vma_debug("%s, return: %Lx, addr: %Lx\n", __func__, ret, new_addr);
	return ret ? ret : new_addr;
}
