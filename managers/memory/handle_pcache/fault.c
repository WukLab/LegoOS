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

#include <lego/profile.h>
#include <lego/fit_ibapi.h>
#include <lego/ratelimit.h>
#include <lego/checksum.h>
#include <lego/profile.h>
#include <lego/comp_memory.h>
#include <lego/comp_storage.h>
#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/thread_pool.h>
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
static void pcache_miss_error(u32 retval, struct lego_task_struct *p,
			      u64 vaddr, struct thpool_buffer *tb)
{
	int *reply = thpool_buffer_tx(tb);

	*reply = retval;
	tb_set_tx_size(tb, sizeof(*reply));

	dump_lego_tasks();
	if (p) {
		pr_info("src_nid:%u,pid:%u,vaddr:%#Lx\n", p->node, p->pid, vaddr);
		dump_all_vmas_simple(p->mm);
	}
	WARN_ON_ONCE(1);
}

/*
 * A common shared routine to handle all pcache misses
 * - normal pcache miss
 * - zerofill request
 *
 * Both of them are valid page fault in traditional concept.
 * We need to establish mapping (e.g. page table) here in memory component.
 */
DEFINE_PROFILE_POINT(pcache_miss_find_vma)

static int common_handle_p2m_miss(struct lego_task_struct *p,
				  u64 vaddr, u32 flags, unsigned long *new_page)
{
	struct vm_area_struct *vma;
	struct lego_mm_struct *mm = p->mm;
	int ret;
	PROFILE_POINT_TIME(pcache_miss_find_vma)

	down_read(&mm->mmap_sem);

	PROFILE_START(pcache_miss_find_vma);
	vma = find_vma(mm, vaddr);
	PROFILE_LEAVE(pcache_miss_find_vma);

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
					u64 vaddr, u32 flags,
					struct thpool_buffer *tb)
{
	int *reply = thpool_buffer_tx(tb);
	int ret;

	ret = common_handle_p2m_miss(p, vaddr, flags, NULL);
	if (unlikely(ret & VM_FAULT_ERROR))
		*reply = -EFAULT;
	else
		*reply = 0;
	tb_set_tx_size(tb, sizeof(int));
}

static void do_handle_p2m_pcache_miss(struct lego_task_struct *p,
				      u64 vaddr, u32 flags,
				      struct thpool_buffer *tb)
{
	int ret;
	unsigned long new_page;

	ret = common_handle_p2m_miss(p, vaddr, flags, &new_page);
	if (unlikely(ret & VM_FAULT_ERROR)) {
		if (ret & VM_FAULT_OOM)
			ret = RET_ENOMEM;
		else if (ret & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
			ret = RET_ESIGSEGV;

		pcache_miss_error(ret, p, vaddr, tb);
		return;
	}

	/*
	 * For normal pcache miss, we do not use the tx.
	 * We simply use the page itself (use private_tx).
	 */
	tb_set_private_tx(tb, (void *)new_page);
	tb_set_tx_size(tb, PCACHE_LINE_SIZE);
}

DEFINE_PROFILE_POINT(handle_flush)

void handle_p2m_flush_one(struct p2m_flush_msg *msg, struct thpool_buffer *tb)
{
	pid_t pid;
	unsigned long user_vaddr, dst_page;
	int reply, src_nid, ret;
	struct lego_task_struct *p;
	PROFILE_POINT_TIME(handle_flush)

	PROFILE_START(handle_flush);

	src_nid = to_common_header(msg)->src_nid;
	pid = msg->pid;
	user_vaddr = msg->user_va;

	p = find_lego_task_by_pid(src_nid, pid);
	if (unlikely(!p)) {
		reply = -ESRCH;
		goto out;
	}

	down_read(&p->mm->mmap_sem);
	ret = get_user_pages(p, msg->user_va, 1, 0, &dst_page, NULL);
	up_read(&p->mm->mmap_sem);
	if (likely(ret == 1)) {
		memcpy((void *)dst_page, msg->pcacheline, PCACHE_LINE_SIZE);
		reply = 0;
	} else
		reply = -EFAULT;

out:
	*(int *)thpool_buffer_tx(tb) = reply;
	tb_set_tx_size(tb, sizeof(int));
	PROFILE_LEAVE(handle_flush);
}

/*
 * Processor counterpart: __pcache_do_fill_page().
 * Check how we fill the information.
 */
static void do_piggyback_flush(void *_msg, unsigned int src_nid,
			       struct lego_task_struct *fault_task)
{
	struct p2m_pcache_miss_flush_combine_msg *pb_msg = _msg;
	struct p2m_flush_msg *flush_msg = &pb_msg->flush;
	struct lego_task_struct *flush_task;
	unsigned long dst_page;
	int ret;

	if (flush_msg->pid == fault_task->pid)
		flush_task = fault_task;
	else {
		flush_task = find_lego_task_by_pid(src_nid, flush_msg->pid);
		if (unlikely(!flush_task)) {
			WARN_ON_ONCE(1);
			return;
		}
	}

	down_read(&flush_task->mm->mmap_sem);
	ret = get_user_pages(flush_task, flush_msg->user_va, 1, 0, &dst_page, NULL);
	up_read(&flush_task->mm->mmap_sem);

	if (likely(ret == 1))
		memcpy((void *)dst_page, flush_msg->pcacheline, PCACHE_LINE_SIZE);
	else
		WARN_ON_ONCE(1);
}

static int fault_in_kernel_space(unsigned long address)
{
	return address >= TASK_SIZE_MAX;
}

DEFINE_PROFILE_POINT(handle_miss)

void handle_p2m_pcache_miss(struct p2m_pcache_miss_msg *msg,
			    struct thpool_buffer *tb)
{
	u32 tgid, flags;
	u64 vaddr;
	unsigned int src_nid;
	struct lego_task_struct *p;
	PROFILE_POINT_TIME(handle_miss)

	src_nid = to_common_header(msg)->src_nid;
	tgid   = msg->tgid;
	flags  = msg->flags;
	vaddr  = msg->missing_vaddr;

	handle_pcache_debug("I nid:%u pid:%u tgid:%u flags:%x vaddr:%#Lx",
		src_nid, msg->pid, tgid, flags, vaddr);

	p = find_lego_task_by_pid(src_nid, tgid);
	if (unlikely(!p)) {
		pr_info("%s(): src_nid: %d tgid: %d\n", __func__, src_nid, tgid);
		pcache_miss_error(RET_ESRCH, p, vaddr, tb);
		return;
	}

	if (unlikely(fault_in_kernel_space(vaddr))) {
		pcache_miss_error(RET_EFAULT, p, vaddr, tb);
		return;
	}

	PROFILE_START(handle_miss);
	do_handle_p2m_pcache_miss(p, vaddr, flags, tb);
	if (msg->has_flush_msg)
		do_piggyback_flush(msg, src_nid, p);
	PROFILE_LEAVE(handle_miss);

	handle_pcache_debug("O nid:%u pid:%u tgid:%u flags:%x vaddr:%#Lx",
		src_nid, msg->pid, tgid, flags, vaddr);
}

void handle_p2m_zerofill(struct p2m_zerofill_msg *msg,
			 struct thpool_buffer *tb)
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
		pcache_miss_error(RET_ESRCH, p, vaddr, tb);
		return;
	}

	if (unlikely(fault_in_kernel_space(vaddr))) {
		pcache_miss_error(RET_EFAULT, p, vaddr, tb);
		return;
	}

	do_handle_p2m_zerofill_miss(p, vaddr, flags, tb);

	handle_zerofill_debug("O nid:%u pid:%u tgid:%u flags:%x vaddr:%#Lx",
		src_nid, msg->pid, tgid, flags, vaddr);
}
