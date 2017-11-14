/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/fit_ibapi.h>
#include <lego/comp_memory.h>
#include <lego/comp_storage.h>

#include <memory/include/vm.h>
#include <memory/include/pid.h>
#include <processor/include/pcache.h>

#ifdef CONFIG_DEBUG_HANDLE_PCACHE
#define pcache_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
static inline void pcache_debug(const char *fmt, ...) { }
#endif

/*
 * Processor manager rely on the length of replied
 * message to know if us succeed or failed.
 */
static void llc_miss_error(u32 retval, u64 desc,
			   struct lego_task_struct *p, u64 vaddr)
{
	WARN(1, "src_nid:%u,pid:%u,vaddr:%#Lx\n", p->node, p->pid, vaddr);
	ibapi_reply_message(&retval, 4, desc);
}

static void bad_area(struct lego_task_struct *p, u64 vaddr, u64 offset, u64 desc)
{
	int retval = RET_ESIGSEGV;
	WARN(1, "src_nid:%u,pid:%u,vaddr:%#Lx\n", p->node, p->pid, vaddr);
	ibapi_reply_message(&retval, 4, desc);
}

static void do_handle_p2m_llc_miss(struct lego_task_struct *p,
				   u64 vaddr, u64 offset, u32 flags, u64 desc)
{
	struct vm_area_struct *vma;
	struct lego_mm_struct *mm = p->mm;
	unsigned long new_page;
	int ret;

	down_read(&mm->mmap_sem);

	vma = find_vma(mm, vaddr);
	if (unlikely(!vma))
		goto unlock;

	/* VMAs except stack */
	if (likely(vma->vm_start <= vaddr))
		goto good_area;

	/* stack? */
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN)))
		goto unlock;

	if (unlikely(expand_stack(vma, vaddr)))
		goto unlock;

	/*
	 * Ok, we have a good vm_area for this memory access,
	 * go for it...
	 */
good_area:
	ret = handle_lego_mm_fault(vma, vaddr, flags, &new_page);
	if (unlikely(ret & VM_FAULT_ERROR)) {
		if (ret & VM_FAULT_OOM)
			ret = RET_ENOMEM;
		else if (ret & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
			ret = RET_ESIGSEGV;

		up_read(&mm->mmap_sem);
		llc_miss_error(ret, desc, p, vaddr);
		return;
	}

	up_read(&mm->mmap_sem);

	ibapi_reply_message((void *)(new_page + offset),
		PCACHE_LINE_SIZE, desc);
	return;

unlock:
	up_read(&mm->mmap_sem);
	bad_area(p, vaddr, offset, desc);
}

#ifdef CONFIG_MEM_PREFETCH
static void do_mmap_prefetch(struct lego_task_struct *p, u64 vaddr,
		u32 flags, u32 nr_pages)
{
	struct vm_area_struct *vma;
	struct lego_mm_struct *mm = p->mm;
	u32 real_nr_pages = nr_pages;
	u32 empty_entries;

	down_read(&mm->mmap_sem);

	vma = find_vma(mm, vaddr);

	if (unlikely(!vma)) {
		goto unlock;
	}

	if (unlikely(vma_is_anonymous(vma))) {
		goto unlock;
	}

	/* file backed pages */
	if (unlikely(round_down(vaddr, PAGE_SIZE) + PAGE_SIZE*nr_pages)
			> vma->vm_end)
		real_nr_pages = (vma->vm_end - round_down(vaddr, PAGE_SIZE))/PAGE_SIZE;

	empty_entries = count_empty_entries(vma, vaddr, real_nr_pages);
	if (5*empty_entries < 4*real_nr_pages)
		goto unlock;
	/* handle_lego_faults */
	handle_lego_mmap_faults(vma, vaddr, flags, real_nr_pages);

unlock:
	up_read(&mm->mmap_sem);
	return;
}
#else
static void do_mmap_prefetch(struct lego_task_struct *p, u64 vaddr,
		u32 flags, u32 nr_pages)
{ }
#endif

static int fault_in_kernel_space(unsigned long address)
{
	return address >= TASK_SIZE_MAX;
}

int handle_p2m_llc_miss(struct p2m_llc_miss_struct *payload, u64 desc,
			struct common_header *hdr)
{
	u32 tgid, pid, nid, flags;
	u64 vaddr, offset;
	struct lego_task_struct *p;

	nid    = hdr->src_nid;
	pid    = payload->pid;
	tgid   = payload->tgid;
	flags  = payload->flags;
	vaddr  = payload->missing_vaddr;
	offset = payload->offset; 

	pcache_debug("I nid:%u pid:%u tgid:%u flags:%x vaddr:%#Lx offset: %#Lx",
		nid, pid, tgid, flags, vaddr, offset);

	p = find_lego_task_by_pid(hdr->src_nid, tgid);
	if (unlikely(!p)) {
		llc_miss_error(RET_ESRCH, desc, p, vaddr);
		return 0;
	}

	if (unlikely(fault_in_kernel_space(vaddr))) {
		llc_miss_error(RET_EFAULT, desc, p, vaddr);
		return 0;
	}

	do_handle_p2m_llc_miss(p, vaddr, offset, flags, desc);

	do_mmap_prefetch(p, vaddr, flags, 1 << PREFETCH_ORDER);

	pcache_debug("O nid:%u pid:%u tgid:%u flags:%x vaddr:%#Lx offset: %#Lx",
		nid, pid, tgid, flags, vaddr, offset);
	return 0;
}

/* 0 on success, -ERRNO on failure */
int handle_p2m_flush_single(void *void_payload, u64 desc, struct common_header *hdr)
{
#define DEBUG_CACHE_TEST

	struct p2m_flush_payload *payload;
	void *pages_content;
	struct lego_task_struct *tsk;
	int retval = 0;
	unsigned long __user round_down_vaddr;
	void *cacheline_to_va_pages;

#ifdef DEBUG_CACHE_TEST
	char *kbuf; /* for debug content only */
	u64 offset;
#endif
	
	payload = (struct p2m_flush_payload *) void_payload;
	pages_content = (void *) (void_payload + sizeof(struct p2m_flush_payload));

	tsk = find_lego_task_by_pid(hdr->src_nid, payload->pid);
	if (unlikely(!tsk)){
		retval = -ESRCH;
		goto out_reply;
	}

	round_down_vaddr = round_down(payload->flush_vaddr,
			       	payload->llc_cacheline_size);
	cacheline_to_va_pages = (void *) round_down_vaddr;

#ifdef DEBUG_CACHE_TEST
	offset = payload->flush_vaddr - round_down_vaddr;
	
	/* for testing */
	kbuf = kmalloc(payload->llc_cacheline_size, GFP_KERNEL);
	if (unlikely(!kbuf)){
		pr_info("Fail to allocate a kbuf for testing.\n");
	}
	memset(kbuf, 0, payload->llc_cacheline_size);
	
	lego_copy_from_user(tsk, kbuf, cacheline_to_va_pages,
			payload->llc_cacheline_size);
	pr_info("string in user pages before flush is [%s]\n", kbuf+offset); /* end testing */
#endif

	/* memory copy should be wrong, copy to user space */
	//memcpy(payload->flush_vaddr, pages_content, payload->llc_cacheline_size);
	lego_copy_to_user(tsk, cacheline_to_va_pages, 
			pages_content, payload->llc_cacheline_size);

#ifdef DEBUG_CACHE_TEST
	/* testing */
	memset(kbuf, 0, payload->llc_cacheline_size);

	lego_copy_from_user(tsk, kbuf, cacheline_to_va_pages,
			payload->llc_cacheline_size);
	pr_info("String in user pages after flush is [%s]\n", kbuf+offset);
#endif

out_reply:
	ibapi_reply_message(&retval, sizeof(retval), desc);
#ifdef DEBUG_CACHE_TEST
	kfree(kbuf);
#endif
	return retval;
}
