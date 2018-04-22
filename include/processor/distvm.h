/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* 
 * virtual address space range for each user process
 * virtual address space is distributed on several memory nodes
 * functions are mainly for pcache miss to find a corresponding 
 * memory node that has data
 *
 *
 * processor_distvm_init: Called when a new mm_struct is created
 * processor_distvm_exit: Called when a mm_struct has no users, to be freed
 * get_memory_node:
 * get_replica_node_by_addr:
 * set_memory_node:
 */

#ifndef _LEGO_PROCESSOR_DISTRIBUTED_VM_H_
#define _LEGO_PROCESSOR_DISTRIBUTED_VM_H_

#include <processor/node.h>
#include <lego/distvm.h>

#ifdef CONFIG_DISTRIBUTED_VMA_PROCESSOR

#define PROCESSOR_VMR_SIZE 	(VMR_COUNT * sizeof(vmr16))

int processor_distvm_init(struct mm_struct *mm, int homenode);
void processor_distvm_exit(struct mm_struct *mm);

int get_memory_node(struct task_struct *p, unsigned long addr);
void set_memory_node(struct mm_struct *mm, unsigned long addr, 
		     unsigned long len, vmr16 node);

static inline int get_replica_node_by_addr(struct task_struct *p, unsigned long addr)
{
	return get_replica_node(p);
}

static inline void 
map_mnode(struct mm_struct *mm, unsigned long addr, unsigned long len, vmr16 node)
{
	set_memory_node(mm, addr, len, node);
}

static inline void 
unmap_mnode(struct mm_struct *mm, unsigned long addr, unsigned long len)
{
	set_memory_node(mm, addr, len, (vmr16)current_memory_home_node());
}

void map_mnode_from_reply(struct mm_struct *mm, struct vmr_map_reply *reply);

static inline void processor_fork_dup_distvm(struct task_struct *tsk,
			 struct mm_struct *mm, struct mm_struct *oldmm)
{
	spin_lock(&oldmm->vmr_lock);
	memcpy(mm->vmrange_map, oldmm->vmrange_map, PROCESSOR_VMR_SIZE);
	spin_unlock(&oldmm->vmr_lock);
}

#ifdef CONFIG_VMA_PROCESSOR_UNITTEST
/* unit test wrap up function */
void prcsr_vma_unit_test(void);
#endif

#else

/*
 * No distributed VMA
 */

static inline void processor_distvm_exit(struct mm_struct *mm)
{
}
static inline int processor_distvm_init(struct mm_struct *mm, int homenode)
{
	return 0;
}

/*
 * Always send everything to memory home node
 */
static inline int get_memory_node(struct task_struct *p, unsigned long addr)
{
#ifdef CONFIG_COMP_PROCESSOR
	return get_memory_home_node(p);
#else
	return CONFIG_DEFAULT_MEM_NODE;
#endif 
}

/*
 * Always send replicas to one memory node
 */
static inline int get_replica_node_by_addr(struct task_struct *p, u64 addr)
{
	return get_replica_node(p);
}

/*
 * No need to set anything
 * It is all determined by home_node and replica_node, and can not be changed.
 */
static inline void set_memory_node(struct mm_struct *mm, unsigned long addr, 
				  unsigned long len, vmr16 node) 
{
}
static inline void processor_fork_dup_distvm(struct task_struct *tsk,
			 struct mm_struct *mm, struct mm_struct *oldmm)
{
}

#endif /* CONFIG_DISTRIBUTED_VMA_PROCESSOR */

#endif /* _LEGO_PROCESSOR_MMAP_H_ */
