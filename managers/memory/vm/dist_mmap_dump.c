/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * all distributed vma dump functions are here
 */
#include <memory/distvm.h> 

void dump_vmas_onetree(struct vma_tree *root)
{
#ifdef CONFIG_DEBUG_VMA_DUMP
	struct vm_area_struct *pos;
	if (!root) {
		vma_debug("[VMAS] WARN: root given is an empty pointer\n");
		return;
	}
	pos = root->mmap;
	vma_debug("[VMAS] range begin: %lx, range end: %lx, "
		  "max_gap: %lx, mnode: %d\n",
		  root->begin, root->end, root->max_gap, root->mnode);
	if (!pos) {
		vma_debug("[VMAS] No vmas in this tree\n");
		return;
	}
	for (; pos; pos = pos->vm_next) {
		vma_debug("[VMAS] start: %lx, end: %lx, "
			  "gap: %lx, vm_flags: %lx\n",
			  pos->vm_start, pos->vm_end, 
			  pos->rb_subtree_gap, pos->vm_flags);
	}
#endif
}

void dump_vmas_onenode(struct lego_mm_struct *mm)
{
#ifdef CONFIG_DEBUG_VMA_DUMP
	struct vma_tree **map = mm->vmrange_map;
	int pid = mm->task->pid;
	int idx = 0;
	vma_debug("[VMAS][%d] ************** vma print start **************\n", pid);
	for (idx = 0; idx < VMR_COUNT; idx++) {
		struct vma_tree *root = map[idx];
		if (!root)
			continue;
		
		dump_vmas_onetree(root);
		idx = vmr_idx(VMR_ALIGN(root->end)) - 1;
	}
	vma_debug("[VMAS][%d] ************* vma print done ****************\n", pid);
#endif
}

void dump_gaps_onenode(struct distvm_node *node)
{
#ifdef CONFIG_DEBUG_VMA_DUMP
	struct list_head *head = &node->list;
	struct vma_tree *pos;
	list_for_each_entry(pos, head, list)
		vma_debug("[GAP] max_gap: %lx, is_fixed: %lx\n", 
			  pos->max_gap, pos->flag & MAP_FIXED);
#endif
}

void dump_reply(struct vmr_map_reply *reply)
{
#ifdef CONFIG_DEBUG_VMA_DUMP
	int i;
	struct vmr_map_struct *entry;
	if (!reply) {
		vma_debug("[REPLY] WARN: given reply is empty, stop printing\n");
		return;
	}
	if (!reply->nr_entry)
		return;

	vma_debug("[REPLY] ************** reply print start **************\n");
	vma_debug("[REPLY] reply count: %d, max count: %d\n", 
				reply->nr_entry, MAX_VMA_REPLY_ENTRY);
	entry = reply->map;
	for (i = 0; i < reply->nr_entry; i++) {
		vma_debug("[REPLY] mnode: %d, start: %lx, len: %lx\n", 
			entry[i].mnode, entry[i].start, entry[i].len);
	}
	vma_debug("[REPLY] ************** reply print done ***************\n");
#endif
}

void dump_alloc_schemes(int count, struct alloc_scheme *scheme)
{
#ifdef CONFIG_DEBUG_VMA_DUMP
	int i;
	if (!scheme) {
		vma_debug("[SCHEME] WARN: given scheme is empty, stop printing\n");
		return;
	}

	vma_debug("[SCHEME] ************** scheme print start **************\n");
	for (i = 0; i < count; i++)
		vma_debug("[SCHEME]: scheme nid: %d, len: %lx\n",
			  scheme[i].nid, scheme[i].len);

	vma_debug("[SCHEME] ************** scheme print done ***************\n");
#endif
}

void dump_new_context(struct lego_mm_struct *mm)
{
#ifdef CONFIG_DEBUG_VMA_DUMP
	vma_debug("[CONTEXT]: mm.mm_rb: %p\n", mm->mm_rb.rb_node);
	vma_debug("[CONTEXT]: mm.mmap: %p\n", mm->mmap);
	vma_debug("[CONTEXT]: mm.begin: %lx\n", mm->mmap_legacy_base);
	vma_debug("[CONTEXT]: mm.end: %lx\n", mm->mmap_base);
	vma_debug("[CONTEXT]: mm.highest_vm_end: %lx\n", mm->highest_vm_end);
#endif
}

void dump_vmpool(struct lego_mm_struct *mm)
{
#ifdef CONFIG_DEBUG_VMA_DUMP
	struct rb_node *pos;
	int pid = mm->task->pid;

	if (RB_EMPTY_ROOT(&mm->vmpool_rb)) {
		vma_debug("[VMPOOL][%d]: tree is empty\n", pid);
		return;
	}
	for (pos = rb_first(&mm->vmpool_rb); pos; pos = rb_next(pos)) {
		struct vm_pool_struct *ent = rb_entry(pos, 
					struct vm_pool_struct, vmr_rb);
		vma_debug("[VMPOOL][%d]: begin: %lx, end: %lx\n", 
				pid, ent->pool_start, ent->pool_end);
	}
#endif
}
