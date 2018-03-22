/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/slab.h>
#include <lego/comp_memory.h>
#include <lego/jiffies.h>
#include <memory/distvm.h> 

/* comprehensive test shouldn't run together with other tests */
#define COMPREHENSIVE_TEST	1
#define DEBUG_MACRO 		!COMPREHENSIVE_TEST
#define DEBUG_FREEPOOL_RBTREE	!COMPREHENSIVE_TEST
#define DEBUG_GAP_LIST		!COMPREHENSIVE_TEST
#define CONTEXT_SWITCH_TEST	!COMPREHENSIVE_TEST

static u16 cases;

#if DEBUG_FREEPOOL_RBTREE 
static int 
freepool_alloc_testmsg(struct rb_root *root, unsigned long addr, 
		       unsigned long len, unsigned long flag)
{
	int ret;

	vma_debug("CASE %u: addr: %Lx, len: %Lx\n", cases, addr, len);
	ret = vmpool_alloc(root, addr, len, flag);
	if (ret == -ENOMEM) {
		vma_debug("CASE %u: fail! ret: %Lx\n", cases, ret);
		return -1;
	}
	vma_debug("CASE %u: success!\n", cases);
	return 0;
}

static int 
freepool_retrieve_testmsg(struct rb_root *root, unsigned long addr, unsigned long end)
{
	int ret;

	vma_debug("CASE %u: addr: %Lx, end: %Lx\n", cases, addr, end);
	ret = vmpool_retrieve(root, addr, end);
	if (ret) {
		vma_debug("CASE %u: fail! ret: %Lx\n", cases, ret);
		return -1;
	}
	vma_debug("CASE %u: success!\n", cases);
	return 0;
}
#endif /* DEBUG_FREEPOOL_RBTREE */

static int freepool_rbtree_test(struct lego_mm_struct *mm)
{
#if DEBUG_FREEPOOL_RBTREE 
	struct rb_root root = mm->vmpool_rb;
	unsigned long addr, len, end;
	unsigned long flag = 0;
	/* 1 */
	vma_debug("************ testing allocation ************\n");
	vma_debug("CASE %u: allocated 1G w/o addr\n", ++cases);
	addr = 0;
	len = VM_GRANULARITY;
	if (freepool_alloc_testmsg(&root, addr, len, flag))
		return -1;
	dump_vmpool(mm);
	/* 2 */
	vma_debug("CASE %u: allocated 1G w/ addr\n", ++cases);
	flag = MAP_FIXED;
	addr = 0x7fff40000000;
	len = VM_GRANULARITY;
	if (freepool_alloc_testmsg(&root, addr, len, flag))
		return -1;
	dump_vmpool(mm);
	/* 3 */
	vma_debug("CASE %u: allocated less than 1G w/ addr, not aligned\n", ++cases);
	flag = MAP_FIXED;
	addr = 0x7ffec0079340;
	len = VM_GRANULARITY >> 1;
	if (freepool_alloc_testmsg(&root, addr, len, flag))
		return -1;
	dump_vmpool(mm);
	/* 4 */
	vma_debug("CASE %u: allocated less than 1G w/ addr, not aligned, cross bound\n",
									++cases);
	flag = MAP_FIXED;
	addr = 0x7ffe30079340;
	len = VM_GRANULARITY >> 1;
	if (freepool_alloc_testmsg(&root, addr, len, flag))
		return -1;
	dump_vmpool(mm);
	/* 5 */
	vma_debug("CASE %u: allocated 2G of pool w/o addr\n", ++cases);
	flag = 0;
	addr = 0;
	len = VM_GRANULARITY << 1;
	if (freepool_alloc_testmsg(&root, addr, len, flag))
		return -1;
	dump_vmpool(mm);
	/* 6 */
	vma_debug("CASE %u: allocated w/ addr, not aligned, from 0\n", ++cases);
	flag = MAP_FIXED;
	addr = 0;
	len = (VM_GRANULARITY << 1) + 0x87593fe;
	if (freepool_alloc_testmsg(&root, addr, len, flag))
		return -1;
	dump_vmpool(mm);
	/* 7 */
	vma_debug("CASE %u: allocated w/ addr, not aligned, with overlap at start\n", ++cases);
	flag = MAP_FIXED;
	addr = VM_GRANULARITY;
	len = (VM_GRANULARITY << 2) + 0x87593fe;
	if (freepool_alloc_testmsg(&root, addr, len, flag))
		return -1;
	dump_vmpool(mm);
	/* 8 */
	vma_debug("CASE %u: allocated w/ addr, not aligned, with overlap at end\n", ++cases);
	flag = MAP_FIXED;
	addr = 0x7ffd70000000;
	len = VM_GRANULARITY + 0x87593fe;
	if (freepool_alloc_testmsg(&root, addr, len, flag))
		return -1;
	dump_vmpool(mm);
	/* 9 */
	vma_debug("CASE %u: allocated w/ addr, not aligned, with overlap at end\n", ++cases);
	flag = MAP_FIXED;
	addr = 0x7ffd30000000;
	len = 0x7fff60000000 - addr;
	if (freepool_alloc_testmsg(&root, addr, len, flag))
		return -1;
	dump_vmpool(mm);
	/* 10 */
	vma_debug("************ testing retrieve ************\n");
	vma_debug("CASE %u: retrieve align to start\n", ++cases);
	addr = 0x140000000;
	end = 0x180000000;
	if (freepool_retrieve_testmsg(&root, addr, end))
		return -1;
	dump_vmpool(mm);
	/* 11 */
	vma_debug("CASE %u: retrieve from 0 and not aligned\n", ++cases);
	addr = 0;
	end = 0x40000000;
	if (freepool_retrieve_testmsg(&root, addr, end))
		return -1;
	dump_vmpool(mm);
	/* 12 */
	vma_debug("CASE %u: retrieve not aligned, create a hole\n", ++cases);
	addr = 0x80000000;
	end = 0x100000000;
	if (freepool_retrieve_testmsg(&root, addr, end))
		return -1;
	dump_vmpool(mm);
	/* 13 */
	vma_debug("CASE %u: retrieve aligned to both\n", ++cases);
	addr = 0x100000000;
	end = 0x140000000;
	if (freepool_retrieve_testmsg(&root, addr, end))
		return -1;
	dump_vmpool(mm);
	/* 14 */
	vma_debug("CASE %u: retrieve aligned to end\n", ++cases);
	addr = 0x7ffd00000000;
	end = 0x7fff00000000;
	if (freepool_retrieve_testmsg(&root, addr, end))
		return -1;
	dump_vmpool(mm);

#endif /* DEBUG_FREEPOOL_RBTREE */
	return 0;
}

static void basic_macro_test(void)
{
#if DEBUG_MACRO
	unsigned long addr=jiffies;
	int node;
	vma_debug("************ basic macro test start ************\n");
	vma_debug("VM_GRANULARITY_ORDER: %d\n", CONFIG_VM_GRANULARITY_ORDER);
	vma_debug("VM_GRANULARITY: %lx\n", VM_GRANULARITY);
	vma_debug("VMR_SHIFT: %d\n", VMR_SHIFT);
	vma_debug("vmr_idx(%Lx) = %Lx\n", addr, vmr_idx(addr));
	vma_debug("last_vmr_idx(%Lx) = %Lx\n", addr, last_vmr_idx(addr));
	vma_debug("last_vmr_idx(%lx) = %lx\n", VM_GRANULARITY, 
						last_vmr_idx(VM_GRANULARITY));
	vma_debug("VMR_COUNT: %lx\n", VMR_COUNT);
	vma_debug("ORIGINAL: %Lx, VMR_ALIGN: %Lx, VMR_OFFSET: %Lx\n",
			addr, VMR_ALIGN(addr), VMR_OFFSET(addr));
	vma_debug("MEMORY_VMR_SIZE: %lu\n", MEMORY_VMR_SIZE);
	vma_debug("NODE_COUNT: %lu\n", NODE_COUNT);
	vma_debug("NODEMAP_SIZE: %lu\n", NODEMAP_SIZE);
	node = 1;
	vma_debug("node: %d, valid: %d\n", node, is_node_valid(node));
	node = 100000000;
	vma_debug("node: %d, valid: %d\n", node, is_node_valid(node));
	node = LEGO_LOCAL_NID;
	vma_debug("LEGO_LOCAL_NID: %d, node: %d, local: %d\n",
			LEGO_LOCAL_NID, node, is_local(node));
	node = LEGO_LOCAL_NID + 2;
	vma_debug("LEGO_LOCAL_NID: %d, node: %d, local: %d\n",
			LEGO_LOCAL_NID, node, is_local(node));
	vma_debug("************ basic macro test done ************\n");
#endif
}

static void gaps_sort_test(struct lego_mm_struct *mm)
{	
#if DEBUG_GAP_LIST
	unsigned long mnode = 3;
	struct distvm_node **node = &mm->node_map[mnode];
	struct vma_tree rt1, rt2, rt3;

	*node = kzalloc(sizeof(struct distvm_node), GFP_KERNEL);
	INIT_LIST_HEAD(&(*node)->list);
	
	vma_debug("************ testing node list sort ************\n");
	if(!mm->node_map[mnode]) {
		vma_debug("CASE %u: node list malloc fail!\n", ++cases);
		return;
	}
	vma_debug("CASE %u: node list malloc success!\n", ++cases);

	INIT_LIST_HEAD(&rt1.list);
	INIT_LIST_HEAD(&rt2.list);
	INIT_LIST_HEAD(&rt3.list);
	rt1.mnode = rt2.mnode = rt3.mnode = 3;

	vma_debug("CASE %u: vma_tree gap list insert gap: 2000\n", ++cases);
	rt2.max_gap = 2000;
	sort_node_gaps(mm, &rt2);
	dump_gaps_onenode(*node);

	vma_debug("CASE %u: vma_tree gap list insert gap: 3000\n", ++cases);
	rt3.max_gap = 3000;
	sort_node_gaps(mm, &rt3);
	dump_gaps_onenode(*node);

	vma_debug("CASE %u: vma_tree gap list insert gap: 1000\n", ++cases);
	rt1.max_gap = 1000;
	sort_node_gaps(mm, &rt1);
	dump_gaps_onenode(*node);

	vma_debug("CASE %u: vma_tree gap from 1000 to 2500, re-insert\n", ++cases);
	rt1.max_gap = 2500;
	sort_node_gaps(mm, &rt1);
	dump_gaps_onenode(*node);

	vma_debug("CASE %u: vma_tree gap from 3000 to 500, re-insert\n", ++cases);
	rt3.max_gap = 500;
	sort_node_gaps(mm, &rt3);
	dump_gaps_onenode(*node);
#endif
}

static void context_switch_test(struct lego_mm_struct *mm)
{
#if CONTEXT_SWITCH_TEST
	struct vma_tree tree;
	tree.vm_rb.rb_node = (void *)0x1000;
	tree.mmap = (void *)0x2000;
	tree.begin = 0x3000;
	tree.end = 0x4000;
	tree.highest_vm_end = 0x5000;
	vma_debug("************ context switch test ************\n");
	load_vma_context(mm, &tree);
	vma_debug("[CONTEXT]: mm.mm_rb: %p, tree.vm_rb: %p\n", 
			mm->mm_rb.rb_node, tree.vm_rb.rb_node);
	vma_debug("[CONTEXT]: mm.mmap: %p, tree.mmap: %p\n", 
			mm->mmap, tree.mmap);
	vma_debug("[CONTEXT]: mm.begin: %lx, tree.begin: %lx\n", 
			mm->mmap_legacy_base, tree.begin);
	vma_debug("[CONTEXT]: mm.end: %lx, tree.end: %lx\n", 
			mm->mmap_base, tree.end);
	vma_debug("[CONTEXT]: mm.highest_vm_end: %lx, tree.highest_vm_end: %lx\n", 
			mm->highest_vm_end, tree.highest_vm_end);

	mm->highest_vm_end = 0x6000;
	mm->mm_rb.rb_node = (void *)0x7000;
	mm->mmap = (void *)0x8000;
	save_vma_context(mm, &tree);
	vma_debug("[CONTEXT]: mm.mm_rb: %p, tree.vm_rb: %p\n", 
			mm->mm_rb.rb_node, tree.vm_rb.rb_node);
	vma_debug("[CONTEXT]: mm.mmap: %p, tree.mmap: %p\n", 
			mm->mmap, tree.mmap);
	vma_debug("[CONTEXT]: mm.highest_vm_end: %lx, tree.highest_vm_end: %lx\n", 
			mm->highest_vm_end, tree.highest_vm_end);
#endif
}

unsigned long consult_fake_gmm(unsigned long request, struct consult_reply* reply)
{
	static int which_node = 0;

	if (CONFIG_MEM_NR_NODES == 1) {
		reply->count = 1;
		reply->scheme[0].nid = LEGO_LOCAL_NID;
		reply->scheme[0].len = request;
		return 0;
	}

	which_node = which_node == 1 ? 0 : 1;
	if (CONFIG_MEM_NR_NODES > 1) {
		if (request <= VM_GRANULARITY) {
			reply->count = 1;
			reply->scheme[0].nid = which_node;
			reply->scheme[0].len = request;
			return 0;
		}

		reply->count = 2;
		reply->scheme[0].nid = 0;
		reply->scheme[0].len = VM_GRANULARITY;
		reply->scheme[1].nid = 1;
		reply->scheme[1].len = request - VM_GRANULARITY;
	}
	return 0;
}

static void comprehensive_test(struct lego_task_struct *tsk)
{
#if COMPREHENSIVE_TEST
	int ret;
	unsigned long flag;
	vma_debug("************ comprehensive test start ************\n");
	ret = distvm_brk_homenode(tsk->mm, 0x663000, 0x3125000);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));
	ret = distvm_brk_homenode(tsk->mm, 0x3788000, VM_GRANULARITY);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));
	ret = distvm_brk_homenode(tsk->mm, 0x3788000 + VM_GRANULARITY, VM_GRANULARITY * 2);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));
	ret = distvm_brk_homenode(tsk->mm, 0x3788000 + VM_GRANULARITY * 3, 0x25000);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));

	flag = MAP_PRIVATE | MAP_FIXED;
	ret = (int)distvm_mmap_homenode(tsk->mm, NULL, 0x473f739000, 0x8c7000, 0, flag, 0);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));
	ret = (int)distvm_mmap_homenode(tsk->mm, NULL, 0x4740000000, 0x8c7000, 0, flag, 0);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));
	ret = (int)distvm_mmap_homenode(tsk->mm, NULL, 0x673f739000, 0x8c7000, 0, flag, 0);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));
	ret = (int)distvm_mmap_homenode(tsk->mm, NULL, 0x6740000000, 0x8c7000, 0, flag, 0);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));
	ret = (int)distvm_mmap_homenode(tsk->mm, NULL, 0x2713739000, 0x670000, 0, flag, 0);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));

	flag = MAP_PRIVATE;
	ret = (int)distvm_mmap_homenode(tsk->mm, NULL, 0, PAGE_SIZE, 0, flag, 0);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));
	ret = (int)distvm_mmap_homenode(tsk->mm, NULL, 0, VM_GRANULARITY * 2, 0, flag, 0);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));

	flag = MREMAP_MAYMOVE;
	/* cross node expand */
	ret = (int)distvm_mremap_homenode(tsk->mm, 0x473f739000, 0x118e000, 0x1190000, flag, -1);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));
	/* cross node shrink */
	ret = (int)distvm_mremap_homenode(tsk->mm, 0x473f739000, 0x1190000, 0x700000, flag, -1);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));
	/* cross range expand */
	ret = (int)distvm_mremap_homenode(tsk->mm, 0x473f739000, 0x700000, 0x1000000, flag, -1);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));
	/* within node expand */
	ret = (int)distvm_mremap_homenode(tsk->mm, 0x2713739000, 0x670000, 0x1000000, flag, -1);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));
	/* cross node move */
	ret = (int)distvm_mremap_homenode(tsk->mm, 0x673f739000, 0x1180000, 0x1190000, flag, -1);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));
	/* within node move */
	ret = (int)distvm_mremap_homenode(tsk->mm, 0x2713739000, 0x600000, 0x1000000, flag, -1);
	memset(tsk->mm->reply, 0, sizeof(struct vmr_map_reply));
	vma_debug("************ comprehensive test end ************\n");
#endif
}

void mem_vma_unittest(void)
{
	/* fake a task struct */
	struct lego_task_struct *tsk;
	cases = 0;

	/* initial setup */
	tsk = kmalloc(sizeof(struct lego_task_struct), GFP_KERNEL); 
	mem_set_memory_home_node(tsk, LEGO_LOCAL_NID);
	tsk->mm = lego_mm_alloc(tsk, NULL);
	if (!tsk->mm) {
		vma_debug("distributed vma initialization failed!\n");
		return;
	}
	tsk->mm->reply = kzalloc(sizeof(struct vmr_map_reply), GFP_KERNEL);
	if (!tsk->mm->reply) {
		vma_debug("distributed vma initialization failed!\n");
		return;
	}
	tsk->pid = 45678; /* some fake pid */
	vma_debug("distributed vma initialization success!\n");
	arch_pick_mmap_layout(tsk->mm);
	dump_vmpool(tsk->mm);

	basic_macro_test();
	context_switch_test(tsk->mm);
	freepool_rbtree_test(tsk->mm);
	gaps_sort_test(tsk->mm);
	comprehensive_test(tsk);

	/* free */
	vma_debug("distributed vma struct free\n");
	distvm_exit_homenode(tsk->mm);
	dump_vmpool(tsk->mm);
	kfree(tsk->mm);
	kfree(tsk);
}
