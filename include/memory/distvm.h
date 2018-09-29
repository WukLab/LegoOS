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

#include <memory/vm.h>

#include <monitor/common.h>

/*
 * this struct keeps track of unmap vm area in with granularity of
 * VM_GRANULARITY, the range is [pool_start, pool_end), root is in
 * lego_mm_struct, this struct should always corresponding to vm
 * range array. More precisely, it's the inverse of vm range array.
 */
struct vm_pool_struct {
	struct rb_node vmr_rb;
	unsigned long pool_start;
	unsigned long pool_end;
};

/* serve for vm range */
#define MEMORY_VMR_SIZE		(VMR_COUNT * sizeof(struct vma_tree *))

/* serve for node_map */
#define NODE_COUNT		(1UL << (sizeof(vmr16) * 8))
#define NODEMAP_SIZE		(NODE_COUNT * sizeof(struct distvm_node *))
#define is_node_valid(node)	(node < NODE_COUNT && node >= 0)
#define is_local(node)		(node == LEGO_LOCAL_NID)

static inline void
set_vmrange_map(struct lego_mm_struct *mm, unsigned long addr,
		unsigned long len, struct vma_tree *vma_tree)
{
	struct vma_tree **map = mm->vmrange_map;
	unsigned long idx = vmr_idx(addr);
	unsigned long end = vmr_idx(VMR_ALIGN(addr + len));
	unsigned long count = end - idx;

	VMA_BUG_ON(idx >= VMR_COUNT);
	memset64((uint64_t *)&map[idx], (uint64_t)vma_tree, count);
}

static inline struct vma_tree *
get_vmatree_by_idx(struct lego_mm_struct *mm, unsigned long idx)
{
#ifdef CONFIG_DEBUG_VMA
	VM_BUG_ON_MM(idx >= VMR_COUNT, mm);
	VM_BUG_ON_MM(!mm->vmrange_map, mm);
#endif
	return mm->vmrange_map[idx];
}

static inline struct vma_tree *
get_vmatree_by_addr(struct lego_mm_struct *mm, unsigned long addr)
{
#ifdef CONFIG_DEBUG_VMA
	VM_BUG_ON_MM(addr > VMR_ALIGN(TASK_SIZE), mm);
#endif
	return get_vmatree_by_idx(mm, vmr_idx(addr));
}

int distvm_init(struct lego_mm_struct *mm);
int distvm_init_homenode(struct lego_mm_struct *mm, bool is_copy);
void distvm_exit(struct lego_mm_struct *mm);
void distvm_exit_homenode(struct lego_mm_struct *mm);

/* vm pool API */
int vmpool_retrieve(struct rb_root *root, unsigned long start, unsigned long end);
unsigned long vmpool_alloc(struct rb_root *root, unsigned long addr,
			   unsigned long len, unsigned long flag);

/* homenode handle API */
unsigned long
distvm_mmap_homenode_noconsult(struct lego_mm_struct *mm, struct lego_file *file,
		     unsigned long addr, unsigned long len, unsigned long prot,
		     unsigned long flag, unsigned long pgoff);
unsigned long
distvm_mmap_homenode(struct lego_mm_struct *mm, struct lego_file *file,
		     unsigned long addr, unsigned long len, unsigned long prot,
		     unsigned long flag, unsigned long pgoff);
int
distvm_brk_homenode(struct lego_mm_struct *mm, unsigned long addr, unsigned long len);
int
distvm_munmap_homenode(struct lego_mm_struct *mm, unsigned long begin, unsigned long len);
unsigned long
distvm_mremap_homenode(struct lego_mm_struct *mm, unsigned long old_addr,
		       unsigned long old_len, unsigned long new_len,
		       unsigned long flag, unsigned long new_addr);

/* non-homenode handle API */
int map_vmatrees(struct lego_mm_struct *mm, int mnode, unsigned long addr,
		 unsigned long len, unsigned long flag);
unsigned long
do_dist_mmap(struct lego_mm_struct *mm, struct lego_file *file,
	     int mnode, unsigned long new_range, unsigned long addr,
	     unsigned long len, unsigned long prot, unsigned long flag,
	     vm_flags_t vm_flags, unsigned long pgoff, unsigned long *max_gap);
int distvm_munmap(struct lego_mm_struct *mm, unsigned long begin,
		  unsigned long len, unsigned long *max_gap);
unsigned long
distvm_mremap_grow(struct lego_task_struct *tsk, unsigned long addr,
		   unsigned long old_len, unsigned long new_len);
unsigned long
do_dist_mremap_move(struct lego_mm_struct *mm, int mnode, unsigned long old_addr,
		    unsigned long old_len, unsigned long new_len,
		    unsigned long new_range, unsigned long *old_max_gap,
		    unsigned long *new_max_gap);
unsigned long
do_dist_mremap_move_split(struct lego_mm_struct *mm, unsigned long old_addr,
			  unsigned long old_len, unsigned long new_addr,
			  unsigned long new_len, unsigned long *old_max_gap,
			  unsigned long *new_max_gap);

/* some helper functions */
void max_gap_update(struct vma_tree *root);
int find_dist_vma_intersection(struct lego_mm_struct *mm,
			       unsigned long begin, unsigned long end);
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

	if (unlikely(!reply)) {
		VMA_WARN(1, "If this message appears during process exit, "
			    "you can safely ignore it\n");
		return NULL;
	}

	if (unlikely(reply->nr_entry >= MAX_VMA_REPLY_ENTRY)) {
		VMA_WARN(1, "If this message appears during process exit, "
			    "you can safely ignore it\n");
		reply->nr_entry = 0;
	}
	return &reply->map[reply->nr_entry++];
}

/* some context switch functions for compatible with original vma */
static inline void
load_vma_context(struct lego_mm_struct *mm, struct vma_tree *root)
{
	mm->mm_rb = root->vm_rb;
	mm->mmap = root->mmap;
	mm->mmap_legacy_base = root->begin;
	mm->mmap_base = root->end;
	mm->highest_vm_end = root->highest_vm_end;
#ifdef CONFIG_DEBUG_VMA_TRACE
	dump_new_context(mm);
#endif
}
static inline void
save_vma_context(struct lego_mm_struct *mm, struct vma_tree *root)
{
	root->vm_rb = mm->mm_rb;
	root->mmap = mm->mmap;
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
unsigned long consult_fake_gmm(unsigned long request, struct consult_reply* reply);
void mem_vma_unittest(void);
#endif /* CONFIG_VMA_MEMORY_UNITTEST */

#endif /* CONFIG_DISTRIBUTED_VMA_MEMORY */
#endif /* _LEGO_MEMORY_DISTRIBUTED_VM_H_ */
