/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/rwsem.h>
#include <lego/slab.h>
#include <lego/rbtree.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/netmacro.h>
#include <lego/comp_memory.h>
#include <lego/fit_ibapi.h>

#include <memory/include/vm.h>
#include <memory/include/pid.h>
#include <memory/include/vm-pgtable.h>
#include <memory/include/file_ops.h>

#ifdef CONFIG_DEBUG_HANDLE_MMAP
#define mmap_debug(fmt, ...)	\
	pr_debug("%s-%s(): " fmt "\n", __FILE__, __func__, __VA_ARGS__)

static void dump_vm_all(struct lego_mm_struct *mm, int enter)
{
	if (enter)
		pr_debug("Before");
	else
		pr_debug("After");
	dump_all_vmas_simple(mm);
}
#else
#define mmap_debug(fmt, ...)	do { } while (0)
static inline void dump_vm_all(struct lego_mm_struct *mm, int enter) { }
#endif

/**
 * Returns: the brk address
 *  ERROR:
 *	RET_ESRCH
 *	RET_EINTR
 */
int handle_p2m_brk(struct p2m_brk_struct *payload, u64 desc,
		   struct common_header *hdr)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	unsigned long min_brk, brk = payload->brk;
	unsigned long newbrk, oldbrk;
	struct lego_task_struct *tsk;
	struct lego_mm_struct *mm;
	unsigned long ret_brk;
	int ret;

	mmap_debug("src_nid: %u, pid: %u, brk: %#lx", nid, pid, brk);

	tsk = find_lego_task_by_pid(nid, pid);
	if (unlikely(!tsk)) {
		ret_brk = RET_ESRCH;
		ibapi_reply_message(&ret_brk, sizeof(ret_brk), desc);
		return 0;
	}
	dump_vm_all(tsk->mm, 1);

	mm = tsk->mm;
	if (down_write_killable(&mm->mmap_sem)) {
		ret_brk = RET_EINTR;
		ibapi_reply_message(&ret_brk, sizeof(ret_brk), desc);
		return 0;
	}

	min_brk = mm->start_brk;
	if (brk < min_brk)
		goto out;

	newbrk = PAGE_ALIGN(brk);
	oldbrk = PAGE_ALIGN(mm->brk);

	/* within same page, great! */
	if (oldbrk == newbrk)
		goto set_brk;

	/* Shrink the brk */
	if (brk <= mm->brk) {
		ret = do_munmap(mm, newbrk, oldbrk - newbrk);
		if (likely(!ret))
			goto set_brk;
		goto out;
	}

	/* Check against existing mmap mappings. */
	if (find_vma_intersection(mm, oldbrk, newbrk+PAGE_SIZE))
		goto out;

	/* Ok, looks good - let it rip. */
	ret = do_brk(tsk, oldbrk, newbrk-oldbrk);
	if (unlikely(ret < 0))
		goto out;

set_brk:
	mm->brk = brk;

	/* Yup, by default, we populate */
	if (newbrk > oldbrk)
		lego_mm_populate(mm, oldbrk, newbrk - oldbrk);

out:
	up_write(&mm->mmap_sem);

	ret_brk = mm->brk;
	ibapi_reply_message(&ret_brk, sizeof(ret_brk), desc);

	dump_vm_all(mm, 0);
	return 0;
}

/**
 * Returns: the virtual address
 *  ERROR:
 *	RET_ESRCH
 */
int handle_p2m_mmap(struct p2m_mmap_struct *payload, u64 desc,
		    struct common_header *hdr)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	u64 addr = payload->addr;
	u64 len = payload->len;
	u64 prot = payload->prot;
	u64 flags = payload->flags;
	u64 pgoff = payload->pgoff;
	char *f_name = payload->f_name;
	struct lego_task_struct *tsk;
	struct lego_file *file = NULL;
	struct p2m_mmap_reply_struct reply;
	s64 ret;

	mmap_debug("src_nid:%u,pid:%u,addr:%#Lx,len:%#Lx,prot:%#Lx,flags:%#Lx"
		    "pgoff:%#Lx,f_name:[%s]", nid, pid, addr, len, prot,
		    flags, pgoff, f_name);

	tsk = find_lego_task_by_pid(nid, pid);
	if (unlikely(!tsk)) {
		reply.ret = RET_ESRCH;
		goto out;
	}
	dump_vm_all(tsk->mm, 1);

	/*
	 * Are we doing a file-backed mmap()?
	 * If so, we need to allocate a lego_file to attach to this vma:
	 */
	if (!(flags & MAP_ANONYMOUS)) {
		file = file_open(tsk, f_name);
		if (IS_ERR(file)) {
			reply.ret = RET_ENOMEM;
			goto out;
		}
	}

	flags &= ~(MAP_EXECUTABLE | MAP_DENYWRITE);
	ret = vm_mmap_pgoff(tsk, file, addr, len, prot, flags, pgoff);

	/* which means vm_mmap_pgoff() returns -ERROR */
	if (unlikely(ret < 0)) {
		reply.ret = ERR_TO_LEGO_RET(ret);
		goto out;
	}

	reply.ret = RET_OKAY;
	reply.ret_addr = (u64)ret;

out:
	ibapi_reply_message(&reply, sizeof(reply), desc);

	dump_vm_all(tsk->mm, 0);
	return 0;
}

int handle_p2m_munmap(struct p2m_munmap_struct *payload, u64 desc,
		      struct common_header *hdr)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	u64 addr = payload->addr;
	u64 len = payload->len;
	struct lego_task_struct *tsk;
	struct lego_mm_struct *mm;
	u64 ret;

	mmap_debug("src_nid:%u, pid:%u, addr:%#Lx, len:%#Lx",
		nid, pid, addr, len);

	tsk = find_lego_task_by_pid(nid, pid);
	if (unlikely(!tsk)) {
		ret = RET_ESRCH;
		goto out;
	}
	dump_vm_all(tsk->mm, 1);

	mm = tsk->mm;
	if (down_write_killable(&mm->mmap_sem)) {
		ret = RET_EINTR;
		goto out;
	}

	ret = do_munmap(mm, addr, len);
	up_write(&mm->mmap_sem);

out:
	ibapi_reply_message(&ret, sizeof(ret), desc);

	dump_vm_all(tsk->mm, 0);
	return 0;
}

int handle_p2m_msync(struct p2m_msync_struct *payload, u64 desc,
		     struct common_header *hdr)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	u64 start = payload->start;
	u64 len = payload->len;
	u64 end = start + len;
	u64 flags = payload->flags;
	struct lego_task_struct *tsk;
	struct lego_mm_struct *mm;
	struct vm_area_struct *vma;
	u32 ret, unmapped_error;

	mmap_debug("src_nid:%u,pid:%u,start:%#Lx,len:%#Lx,flags:%#Lx",
		nid, pid, start, len, flags);

	tsk = find_lego_task_by_pid(nid, pid);
	if (unlikely(!tsk)) {
		ret = RET_ESRCH;
		goto out;
	}
	dump_vm_all(tsk->mm, 1);

	/*
	 * If the interval [start,end) covers some unmapped address ranges,
	 * just ignore them, but return -ENOMEM at the end.
	 */
	mm = tsk->mm;
	down_read(&mm->mmap_sem);
	vma = find_vma(mm, start);
	for (;;) {
		struct lego_file *file;
		loff_t fstart, fend;

		ret = -ENOMEM;
		if (!vma)
			goto out_unlock;

		/* Here start < vma->vm_end. */
		if (start < vma->vm_start) {
			start = vma->vm_start;
			if (start >= end)
				goto out_unlock;
			unmapped_error = -ENOMEM;
		}

		file = vma->vm_file;

		fstart = (start - vma->vm_start) +
			 ((loff_t)vma->vm_pgoff << PAGE_SHIFT);
		fend = fstart + (min((unsigned long)end, vma->vm_end) - start) - 1;

		start = vma->vm_end;
		if ((flags & MS_SYNC) && file &&
				(vma->vm_flags & VM_SHARED)) {
			up_read(&mm->mmap_sem);
			/*
			 * TODO:
			 * How we gonna impl msync without buffer cache?
			 * What about mmaped files?
			 */
			//ret = vfs_fsync_range(file, fstart, fend, 1);
			if (ret || start >= end)
				goto out;
			down_read(&mm->mmap_sem);
			vma = find_vma(mm, start);
		} else {
			if (start >= end) {
				ret = 0;
				goto out_unlock;
			}
			vma = vma->vm_next;
		}
	}

out_unlock:
	up_read(&mm->mmap_sem);
out:
	if (unmapped_error)
		ret = unmapped_error;
	ibapi_reply_message(&ret, sizeof(ret), desc);

	dump_vm_all(tsk->mm, 0);
	return 0;
}

int handle_p2m_mprotect(struct p2m_mprotect_struct *payload, u64 desc,
			struct common_header *hdr)
{
	WARN_ON(1);
	return 0;
}
