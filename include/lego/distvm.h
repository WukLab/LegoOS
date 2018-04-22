/*
 * Copyright (c) 2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_DISTRIBUTED_VM_H_
#define _LEGO_DISTRIBUTED_VM_H_

/*
* vma debug options
*/
#ifdef CONFIG_DEBUG_VMA

#define VMA_DEBUG
#define vma_debug(...)			pr_debug("VMA: " __VA_ARGS__)
#define VMA_BUG_ON(cond)		BUG_ON(cond)
#define VMA_WARN_ON(cond)		WARN_ON(cond)
#define VMA_WARN(cond, format...)	WARN(cond, format)

#ifdef CONFIG_DEBUG_VMA_TRACE
#define vma_trace(...)			pr_debug("VMA: " __VA_ARGS__)
#else
#define vma_trace(...)			do { } while (0)
#endif

#else

#define vma_debug(...)			do { } while (0)
#define vma_trace(...)			do { } while (0)
#define VMA_BUG_ON(cond)		do { } while (0)
#define VMA_WARN_ON(cond)		do { } while (0)
#define VMA_WARN(cond, format...)	do { } while (0)

#endif /* CONFIG_DEBUG_VMA */

/*
 * this type def restrict the maximal possible
 * memory node connected
 * unsigned short allow 65536 nodes connect simultaneously
*/
typedef unsigned short vmr16;

/* individual reply entry */
struct vmr_map_struct {
	vmr16 mnode;
	unsigned long start;
	unsigned long len;
};

/*
 * since reply needs a fixed size, maximum entry restrict to number
 * of fit node * 2 (remap can possibly have two continuous ranges
 * changed for one node). nr_entry represent the real number of entries
 * that are valid
 */
#define MAX_VMA_REPLY_ENTRY	(CONFIG_FIT_NR_NODES * 2)

struct vmr_map_reply {
	vmr16 nr_entry;
	struct vmr_map_struct map[MAX_VMA_REPLY_ENTRY];
};

#ifdef CONFIG_VM_GRANULARITY_ORDER
# define VM_GRANULARITY		(1UL << CONFIG_VM_GRANULARITY_ORDER)
#else
# define VM_GRANULARITY		(1UL << 30)
#endif

#define VMR_SHIFT 		(CONFIG_VM_GRANULARITY_ORDER)

/* to align the pointer to the (next) VM_GRANULARITY boundary */
#define VMR_ALIGN(addr)		ALIGN((addr), VM_GRANULARITY)

/* to align the pointer to the (current) VM_GRANULARITY boundary */
#define VMR_OFFSET(addr)	((addr) & ~(VM_GRANULARITY - 1))
#define vmr_idx(addr)		((unsigned long)((addr) >> VMR_SHIFT))
#define VMR_COUNT		vmr_idx(VMR_ALIGN(TASK_SIZE))

/* index pointer to last valid vm range base on end addr */
#define last_vmr_idx(end)	(vmr_idx(end) - (typeof(end))(VMR_ALIGN(end) == (end)))

#endif /* _LEGO_DISTRIBUTED_VM_H_ */
