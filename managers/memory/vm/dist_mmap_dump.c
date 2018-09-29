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
#include <lego/mm.h>
#include <memory/mm.h>
#include <memory/distvm.h>

void dump_vmas_onetree(struct vma_tree *root)
{
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
}

void dump_vmas_onenode(struct lego_mm_struct *mm)
{
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
}

void dump_gaps_onenode(struct lego_mm_struct *mm, unsigned long id)
{
	struct distvm_node *node;
	struct list_head *head;
	struct vma_tree *pos;

	if (!mm->node_map) {
		vma_debug("[GAP] node_map isn't allocated\n");
		return;
	}

	if (id >= NODE_COUNT) {
		vma_debug("[GAP] node id given is invalid\n");
		return;
	}

	node = mm->node_map[id];
	if (!node) {
		vma_debug("[GAP] given node doesn't exist\n");
		return;
	}

	head = &node->list;
	list_for_each_entry(pos, head, list)
		vma_debug("[GAP] max_gap: %lx, is_fixed: %lx\n",
			  pos->max_gap, pos->flag & MAP_FIXED);
}

void dump_reply(struct vmr_map_reply *reply)
{
#ifdef CONFIG_DEBUG_VMA_TRACE
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
}

void dump_new_context(struct lego_mm_struct *mm)
{
	vma_debug("[CONTEXT]: mm.mm_rb: %p\n", mm->mm_rb.rb_node);
	vma_debug("[CONTEXT]: mm.mmap: %p\n", mm->mmap);
	vma_debug("[CONTEXT]: mm.begin: %lx\n", mm->mmap_legacy_base);
	vma_debug("[CONTEXT]: mm.end: %lx\n", mm->mmap_base);
	vma_debug("[CONTEXT]: mm.highest_vm_end: %lx\n", mm->highest_vm_end);
}

void dump_vmpool(struct lego_mm_struct *mm)
{
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
}

#ifdef CONFIG_DEBUG_VMA
static int distribute_validation(struct lego_task_struct *tsk, unsigned long addr,
				 unsigned long len, int mnode)
{
	int ret, reply = 0;
	struct m2m_validate_struct send;

	send.pid = tsk->pid;
	send.prcsr_nid = tsk->node;
	send.addr = addr;
	send.len = len;

	ret = net_send_reply_timeout(mnode, M2M_VALIDATE, (void *)&send,
			sizeof(struct m2m_validate_struct), (void *)&reply,
			sizeof(int), false, DEF_NET_TIMEOUT);

	if (ret != sizeof(reply))
		return -EIO;

	return reply;
}
#endif

void mmap_brk_validate_local(struct lego_mm_struct *mm, unsigned long addr, unsigned long len)
{
#ifdef CONFIG_DEBUG_VMA
	const unsigned long end = addr + len;
	struct vm_area_struct *vma, *prev = NULL;

	vma_trace("nid: %d, pid: %d, Validate addr: %lx, end: %lx\n",
		  mm->task->node, mm->task->node, addr, end);

new_tree:
	vma = find_vma(mm, addr);
	if (!vma || vma->vm_start > addr) {
		vma_debug("Addr: %lx not found\n", addr);
		dump_all_vmas_simple(mm);
		BUG();
	}

	while (vma && vma->vm_end < end) {
		struct vma_tree *root = mm->vmrange_map[vmr_idx(vma->vm_start)];

		/* if there is prev, check continuity */
		if (prev && prev->vm_end != vma->vm_start) {
			vma_debug("Addr: %lx not found\n", prev->vm_end);
			dump_all_vmas_simple(mm);
			BUG();
		}

		/* good, return */
		if (vma->vm_end >= end)
			return;

		prev = vma;
		if (root->end == vma->vm_end) {
			/*
			 * out of current tree range,
			 * proceed to next vma tree
			 */
			addr = vma->vm_end;
			goto new_tree;
		} else if (root->end < vma->vm_end) {
			vma_debug("vma exceeds vma tree range, root->end: %lx,"
			          "vma->vm_end: %lx\n", root->end, vma->vm_end);
			dump_all_vmas_simple(mm);
			BUG();
		} else {
			vma = vma->vm_next;
		}
	}
#endif
}

void mmap_brk_validate(struct lego_mm_struct *mm, unsigned long addr, unsigned long len)
{
#ifdef CONFIG_DEBUG_VMA
	const unsigned long end = addr + len;
	struct vm_area_struct *vma, *prev = NULL;
	struct vma_tree *root;

	vma_trace("nid: %d, pid: %d, Validate addr: %lx, end: %lx\n",
		  mm->task->node, mm->task->pid, addr, end);

new_tree:
	root = get_vmatree_by_addr(mm, addr);
	vma = find_vma(mm, addr);
	/* vma is not local, we need to send the validation to remote */
	if (!vma && root) {
		unsigned long send_len = min(root->end, end) - addr;
		int ret;

		ret = distribute_validation(mm->task, addr, send_len, root->mnode);
		if (ret) {
			vma_debug("Return result: %d\n", ret);
			dump_all_vmas_simple(mm);
			BUG();
		}

		addr += send_len;
		if (addr == end)
			return;

		goto new_tree;
	}

	/* vma is local to homenode, check it now */
	if (!vma || vma->vm_start > addr) {
		vma_debug("Addr: %lx not found\n", addr);
		dump_all_vmas_simple(mm);
		BUG();
	}

	while (vma && vma->vm_end < end) {
		struct vma_tree *root = mm->vmrange_map[vmr_idx(vma->vm_start)];

		/* if there is prev, check continuity */
		if (prev && prev->vm_end != vma->vm_start) {
			vma_debug("Addr: %lx not found\n", prev->vm_end);
			dump_all_vmas_simple(mm);
			BUG();
		}

		/* good, return */
		if (vma->vm_end >= end)
			return;

		prev = vma;
		if (root->end == vma->vm_end) {
			/*
			 * out of current tree range,
			 * proceed to next vma tree
			 */
			addr = vma->vm_end;
			goto new_tree;
		} else if (root->end < vma->vm_end) {
			vma_debug("vma exceeds vma tree range, root->end: %lx,"
			          "vma->vm_end: %lx\n", root->end, vma->vm_end);
			dump_all_vmas_simple(mm);
			BUG();
		} else {
			vma = vma->vm_next;
		}
	}
#endif
}
