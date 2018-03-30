/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MEMORY_DISTRIBUTED_VM_H_
#define _LEGO_MEMORY_DISTRIBUTED_VM_H_

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY 

#include <lego/rbtree.h>
#include <lego/string.h>
#include <lego/distvm.h>
#include <lego/fit_ibapi.h>

#include <memory/task.h>

/*
 * this struct keeps track of unmap vm area in with granularity of 
 * VM_GRANULARITY, the range is [pool_start, pool_end), root is in 
 * lego_mm_struct, this struct should always corresponding to vm 
 * range array. More precisely, it's the inverse of vm range array. 
 */
struct vm_pool_struct {
	struct rb_node vmr_rb;
	__u64 pool_start;
	__u64 pool_end;
};

/* serve for vm range */
#define MEMORY_VMR_SIZE		(VMR_COUNT * sizeof(struct vma_tree *))

/* serve for node_map */
#define NODE_COUNT		(1UL << (sizeof(vmr16) * 8))
#define NODEMAP_SIZE		(NODE_COUNT * sizeof(struct distvm_node *))
#define is_node_valid(node)	(node < NODE_COUNT && node >= 0)
#define is_local(node)		(node == MY_NODE_ID)

static inline void
set_vmrange_map(struct lego_mm_struct *mm, u64 addr, u64 len, struct vma_tree *vma_tree)
{
	struct vma_tree **map = mm->vmrange_map;
	u64 idx = vmr_idx(addr);
	u64 end = vmr_idx(VMR_ALIGN(addr + len));
	u64 count = end - idx;

	VMA_BUG_ON(idx >= VMR_COUNT);
	memset64((uint64_t *)&map[idx], (uint64_t)vma_tree, count);
}

int distvm_init(struct lego_mm_struct *mm);
int distvm_init_homenode(struct lego_mm_struct *mm);
void distvm_exit(struct lego_mm_struct *mm);
void distvm_exit_homenode(struct lego_mm_struct *mm);

/* debugging functions */
void dump_vmas_onetree(struct vma_tree *root);
void dump_vmas_onenode(struct lego_mm_struct *mm);
void dump_gaps_onenode(struct distvm_node *node);
void dump_reply(struct vmr_map_reply *reply);

/* dealing with pool */
int vmpool_retrieve(struct rb_root *root, u64 start, u64 end);
u64 vmpool_alloc(struct rb_root *root, u64 addr, u64 len, u64 flag);

/* homenode handle API */
u64 distvm_mmap_homenode(struct lego_mm_struct *mm, struct lego_file *file, 
			 u64 addr, u64 len, u64 prot, u64 flag, u64 pgoff);
u64 distvm_brk_homenode(struct lego_mm_struct *mm, u64 addr, u64 len);
int distvm_munmap_homenode(struct lego_mm_struct *mm, u64 begin, u64 len);
u64 distvm_mremap_homenode(struct lego_mm_struct *mm, u64 old_addr, 
			   u64 old_len, u64 new_len, u64 flag, u64 new_addr);

/* non-homenode handle API */
u64 
map_vmatrees(struct lego_mm_struct *mm, u64 mnode, u64 addr, u64 len, u32 flag);
u64 do_dist_mmap(struct lego_mm_struct *mm, struct lego_file *file,
	     u64 mnode, u64 new_range, u64 addr, u64 len, u64 prot, 
	     u64 flag, vm_flags_t vm_flags, u64 pgoff, u64 *max_gap);
int distvm_munmap(struct lego_mm_struct *mm, u64 begin, u64 len, u64 *max_gap);
u64 distvm_mremap_grow(struct lego_task_struct *tsk, 
		       u64 addr, u64 old_len, u64 new_len);
u64 do_dist_mremap_move(struct lego_mm_struct *mm, u64 mnode, 
		u64 old_addr, u64 old_len, u64 new_len, u64 new_range, 
		u64 *old_max_gap, u64 *new_max_gap);
u64 do_dist_mremap_move_split(struct lego_mm_struct *mm, u64 old_addr, 
			  u64 old_len, u64 new_addr, u64 new_len, 
			  u64 *old_max_gap, u64 *new_max_gap);

/* some helper functions */
void max_gap_update(struct vma_tree *root);
bool find_dist_vma_intersection(struct lego_mm_struct *mm, u64 begin, u64 end);
/* only use this function at homenode */
void sort_node_gaps(struct lego_mm_struct *mm, struct vma_tree *root);

/* vma reply buffer manipulation functions */
static inline void
load_reply_buffer(struct lego_mm_struct *mm, struct vmr_map_reply *reply)
{
	reply->nr_entry = 0;
	mm->reply = reply;
}
static inline void
remove_reply_buffer(struct lego_mm_struct *mm)
{
	mm->reply = NULL;
}
static inline struct vmr_map_struct *
get_available_reply_entry(struct lego_mm_struct *mm)
{
	struct vmr_map_reply *reply = mm->reply;
	BUG_ON(reply->nr_entry >= MAX_VMA_REPLY_ENTRY);
	return &reply->map[reply->nr_entry++];
}

/* some context switch functions for compatible with original vma */
static inline void 
load_vma_context(struct lego_mm_struct *mm, struct vma_tree *root)
{
	memcpy(&mm->mm_rb, &root->vm_rb, sizeof(struct rb_root));
	mm->mmap = root->mmap;
	mm->mmap_legacy_base = root->begin;
	mm->mmap_base = root->end;
	mm->highest_vm_end = root->highest_vm_end;
}
static inline void 
save_vma_context(struct lego_mm_struct *mm, struct vma_tree *root)
{
	root->mmap = mm->mmap;
	memcpy(&root->vm_rb, &mm->mm_rb, sizeof(struct rb_root));
	root->highest_vm_end = mm->highest_vm_end;
}
static inline void 
save_update_vma_context(struct lego_mm_struct *mm, struct vma_tree *root)
{
	save_vma_context(mm, root);
	max_gap_update(root);
}

#ifdef CONFIG_VMA_MEMORY_UNITTEST
/* unit test entrance */
void mem_vma_unittest(void);
#endif /* CONFIG_VMA_MEMORY_UNITTEST */

#endif /* CONFIG_DISTRIBUTED_VMA_MEMORY */
#endif /* _LEGO_MEMORY_DISTRIBUTED_VM_H_ */
