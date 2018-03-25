/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Serving distributed vma, this file defines functions for finding 
 * vm range on each memory node, helps serving pcache miss
 */

#include <lego/slab.h>
#include <lego/string.h>
#include <lego/spinlock.h>
#include <processor/distvm.h>

int distvm_init(struct mm_struct *mm, int homenode)
{
	spin_lock_init(&mm->vmr_lock);
	mm->vmrange_map = kmalloc(PROCESSOR_VMR_SIZE, GFP_KERNEL);
	if (unlikely(!mm->vmrange_map))
		return -ENOMEM;

	memset16(mm->vmrange_map, (vmr16)homenode, VMR_COUNT);
	return 0;
}

/* 
 * used for page fault find
 */
int get_memory_node(struct mm_struct *mm, u64 addr)
{
	vmr16 node;
	vmr16 *map = mm->vmrange_map;
	u64 idx = vmr_idx(addr);
	
	VMA_BUG_ON(idx >= VMR_COUNT);

	spin_lock(&mm->vmr_lock);
	node = map[idx];
	spin_unlock(&mm->vmr_lock);

	return (int)node;
}

void set_memory_node(struct mm_struct *mm, u64 addr, u64 len, vmr16 node)
{
	vmr16 *map = mm->vmrange_map;
	u64 idx = vmr_idx(addr);
	u64 end = vmr_idx(VMR_ALIGN(addr + len));
	u64 cpylen = end - idx;

	VMA_BUG_ON(idx >= VMR_COUNT);
	VMA_BUG_ON(end > VMR_COUNT);

	/* this needs to be change if vmr16 size changed */
	spin_lock(&mm->vmr_lock);
	memset16(&map[idx], node, cpylen);
	spin_unlock(&mm->vmr_lock);
}

void map_mnode_from_reply(struct mm_struct *mm, struct vmr_map_reply *reply)
{
	int i;

	vma_debug("reply count: %d\n", reply->nr_entry);
	for (i = 0; i < reply->nr_entry; i++) {
		struct vmr_map_struct *entry = reply->map;
		vma_debug("[DUMP] mnode: %d, start: %lx, len: %lx\n", 
			entry[i].mnode, entry[i].start, entry[i].len);

		map_mnode(mm, entry[i].start, entry[i].len, entry[i].mnode);
	}
}
