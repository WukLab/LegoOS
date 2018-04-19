/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file describes routines for handling
 *	pcache line fetch.
 */

#include <lego/fit_ibapi.h>
#include <lego/ratelimit.h>
#include <lego/checksum.h>
#include <lego/comp_memory.h>
#include <lego/comp_storage.h>
#include <memory/vm.h>
#include <memory/pid.h>
#include <processor/pcache.h>

#include "internal.h"

#ifdef CONFIG_DEBUG_HANDLE_PCACHE_FILL
static DEFINE_RATELIMIT_STATE(handle_pcache_debug_rs,
	DEFAULT_RATELIMIT_INTERVAL, DEFAULT_RATELIMIT_BURST);

#define handle_pcache_debug(fmt, ...)					\
({									\
	if (__ratelimit(&handle_pcache_debug_rs))			\
		pr_debug("%s() cpu%2d " fmt "\n",			\
			__func__, smp_processor_id(), __VA_ARGS__);	\
})
#else
static inline void handle_pcache_debug(const char *fmt, ...) { }
#endif

#ifdef CONFIG_DEBUG_HANDLE_ZEROFILL
#define handle_zerofill_debug(fmt, ...)				\
	pr_debug("%s() cpu%2d " fmt "\n",			\
		__func__, smp_processor_id(), __VA_ARGS__)
#else
static inline void handle_zerofill_debug(const char *fmt, ...) { }
#endif

/*
 * Processor manager rely on the length of replied
 * message to know if us succeed or failed.
 */
static void pcache_miss_error(u32 retval, u64 desc,
			   struct lego_task_struct *p, u64 vaddr, void *tx)
{
	int *reply = tx;

	*reply = retval;
	ibapi_reply_message(reply, sizeof(*reply), desc);

	dump_all_vmas_simple(p->mm);
	WARN(1, "src_nid:%u,pid:%u,vaddr:%#Lx\n", p->node, p->pid, vaddr);
}

/*
 * A common shared routine to handle all pcache misses
 * - normal pcache miss
 * - zerofill request
 *
 * Both of them are valid page fault in traditional concept.
 * We need to establish mapping (e.g. page table) here in memory component.
 */
static int common_handle_p2m_miss(struct lego_task_struct *p,
				  u64 vaddr, u32 flags, u64 desc,
				  unsigned long *new_page)
{
	struct vm_area_struct *vma;
	struct lego_mm_struct *mm = p->mm;
	int ret;

	down_read(&mm->mmap_sem);

	vma = find_vma(mm, vaddr);
	if (unlikely(!vma)) {
		pr_info("fail to find vma\n");
		ret = VM_FAULT_SIGSEGV;
		goto unlock;
	}

	/* VMAs except stack */
	if (likely(vma->vm_start <= vaddr))
		goto good_area;

	/* stack? */
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
		pr_info("not a stack\n");
		ret = VM_FAULT_SIGSEGV;
		goto unlock;
	}

	if (unlikely(expand_stack(vma, vaddr))) {
		pr_info("fail to expand stack\n");
		ret = VM_FAULT_SIGSEGV;
		goto unlock;
	}

	/*
	 * Okay, now we have a good vma, which means this is a valid
	 * missing address. Now, calling back to underlying handler
	 * to establish mapping. The underlying hook can have its
	 * own choice of mapping: pgtable, segment etc.
	 */
good_area:
	ret = handle_lego_mm_fault(vma, vaddr, flags, new_page, NULL);
unlock:
	up_read(&mm->mmap_sem);
	return ret;
}

static void do_handle_p2m_zerofill_miss(struct lego_task_struct *p,
					u64 vaddr, u32 flags, u64 desc, void *tx)
{
	int *reply = tx;
	int ret;

	ret = common_handle_p2m_miss(p, vaddr, flags, desc, NULL);
	if (unlikely(ret & VM_FAULT_ERROR))
		*reply = -EFAULT;
	else
		*reply = 0;
	ibapi_reply_message(reply, sizeof(*reply), desc);
}

static void do_handle_p2m_pcache_miss(struct lego_task_struct *p,
				      u64 vaddr, u32 flags, u64 desc, void *tx)
{
	int ret;
	unsigned long new_page;

	ret = common_handle_p2m_miss(p, vaddr, flags, desc, &new_page);
	if (unlikely(ret & VM_FAULT_ERROR)) {
		if (ret & VM_FAULT_OOM)
			ret = RET_ENOMEM;
		else if (ret & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
			ret = RET_ESIGSEGV;

		pcache_miss_error(ret, desc, p, vaddr, tx);
		return;
	}

	/*
	 * For normal pcache miss, we do not use the rx buffer.
	 * We simply use the page itself.
	 */
	ibapi_reply_message((void *)new_page, PCACHE_LINE_SIZE, desc);
}

static int fault_in_kernel_space(unsigned long address)
{
	return address >= TASK_SIZE_MAX;
}

int handle_p2m_pcache_miss(struct p2m_pcache_miss_msg *msg, u64 desc, void *tx)
{
	u32 tgid, flags;
	u64 vaddr;
	unsigned int src_nid;
	struct lego_task_struct *p;

	src_nid = to_common_header(msg)->src_nid;
	tgid   = msg->tgid;
	flags  = msg->flags;
	vaddr  = msg->missing_vaddr;

	handle_pcache_debug("I nid:%u pid:%u tgid:%u flags:%x vaddr:%#Lx",
		src_nid, msg->pid, tgid, flags, vaddr);

	p = find_lego_task_by_pid(src_nid, tgid);
	if (unlikely(!p)) {
		pcache_miss_error(RET_ESRCH, desc, p, vaddr, tx);
		return 0;
	}

	if (unlikely(fault_in_kernel_space(vaddr))) {
		pcache_miss_error(RET_EFAULT, desc, p, vaddr, tx);
		return 0;
	}

	do_handle_p2m_pcache_miss(p, vaddr, flags, desc, tx);
	do_mmap_prefetch(p, vaddr, flags, 1 << PREFETCH_ORDER);

	handle_pcache_debug("O nid:%u pid:%u tgid:%u flags:%x vaddr:%#Lx",
		src_nid, msg->pid, tgid, flags, vaddr);
	return 0;
}

void handle_p2m_zerofill(struct p2m_zerofill_msg *msg, u64 desc, void *tx)
{
	u32 tgid, flags;
	u64 vaddr;
	unsigned int src_nid;
	struct lego_task_struct *p;

	src_nid = to_common_header(msg)->src_nid;
	tgid   = msg->tgid;
	flags  = msg->flags;
	vaddr  = msg->missing_vaddr;

	handle_zerofill_debug("I nid:%u pid:%u tgid:%u flags:%x vaddr:%#Lx",
		src_nid, msg->pid, tgid, flags, vaddr);

	p = find_lego_task_by_pid(src_nid, tgid);
	if (unlikely(!p)) {
		pcache_miss_error(RET_ESRCH, desc, p, vaddr, tx);
		return;
	}

	if (unlikely(fault_in_kernel_space(vaddr))) {
		pcache_miss_error(RET_EFAULT, desc, p, vaddr, tx);
		return;
	}

	do_handle_p2m_zerofill_miss(p, vaddr, flags, desc, tx);

	handle_zerofill_debug("O nid:%u pid:%u tgid:%u flags:%x vaddr:%#Lx",
		src_nid, msg->pid, tgid, flags, vaddr);
}
