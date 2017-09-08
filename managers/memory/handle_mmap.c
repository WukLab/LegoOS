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
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)

static void debug_dump_vm_all(struct lego_mm_struct *mm, int enter)
{
	if (enter)
		pr_debug("Before handling\n");
	else
		pr_debug("After handling\n");
	dump_all_vmas_simple(mm);
}
#else
static inline void mmap_debug(const char *fmt, ...) { }
static inline void debug_dump_vm_all(struct lego_mm_struct *mm, int enter) { }
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
	debug_dump_vm_all(tsk->mm, 1);

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

	debug_dump_vm_all(mm, 0);
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
	debug_dump_vm_all(tsk->mm, 1);

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

	debug_dump_vm_all(tsk->mm, 0);
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
	debug_dump_vm_all(tsk->mm, 1);

	mm = tsk->mm;
	if (down_write_killable(&mm->mmap_sem)) {
		ret = RET_EINTR;
		goto out;
	}

	ret = do_munmap(mm, addr, len);
	up_write(&mm->mmap_sem);

out:
	ibapi_reply_message(&ret, sizeof(ret), desc);

	debug_dump_vm_all(tsk->mm, 0);
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
	debug_dump_vm_all(tsk->mm, 1);

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

	debug_dump_vm_all(tsk->mm, 0);
	return 0;
}

static struct vm_area_struct *
vma_to_resize(unsigned long addr, unsigned long old_len,
	      unsigned long new_len, struct lego_task_struct *tsk)
{
	struct lego_mm_struct *mm = tsk->mm;
	struct vm_area_struct *vma;
	unsigned long pgoff;

	vma = find_vma(mm, addr);
	if (!vma || vma->vm_start > addr)
		return ERR_PTR(-EFAULT);

	/* We can't remap across vm area boundaries */
	if (old_len > vma->vm_end - addr)
		return ERR_PTR(-EFAULT);

	if (new_len == old_len)
		return vma;

	/* Overflowed? */
	pgoff = (addr - vma->vm_start) >> PAGE_SHIFT;
	pgoff += vma->vm_pgoff;
	if (pgoff + (new_len >> PAGE_SHIFT) < pgoff)
		return ERR_PTR(-EINVAL);

	/* Can it have more memory? */
	if (!may_expand_vm(mm, vma->vm_flags,
				(new_len - old_len) >> PAGE_SHIFT))
		return ERR_PTR(-ENOMEM);

	return vma;
}

static void mremap_to(unsigned long addr, unsigned long old_len,
		      unsigned long new_addr, unsigned long new_len,
		      struct lego_task_struct *tsk,
		      struct p2m_mremap_reply_struct *reply)
{
	struct lego_mm_struct *mm = tsk->mm;
	struct vm_area_struct *vma;
	unsigned long map_flags;
	unsigned long ret;

	if (offset_in_page(new_addr)) {
		reply->status = RET_EINVAL;
		return;
	}

	if (new_len > TASK_SIZE || new_addr > TASK_SIZE - new_len) {
		reply->status = RET_EINVAL;
		return;
	}

	/* Try to clear the existing mapping if any: */
	ret = do_munmap(mm, new_addr, new_len);
	if (ret) {
		WARN_ON_ONCE(1);
		reply->status = ERR_TO_LEGO_RET(ret);
		reply->line = __LINE__;
		return;
	}

	/*
	 * Try to shrink the old length to new length
	 * 	old_len <= new_len
	 * Hence, it is either 1) remap whole region with
	 * the length, or 2) remap whole region with extended length
	 */
	if (old_len >= new_len) {
		ret = do_munmap(mm, addr + new_len, old_len - new_len);
		if (ret && old_len != new_len) {
			WARN_ON_ONCE(1);
			reply->status = ERR_TO_LEGO_RET(ret);
			reply->line = __LINE__;
			return;
		}
		old_len = new_len;
	}

	/* Try to find a doable vma */
	vma = vma_to_resize(addr, old_len, new_len, tsk); 
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		reply->status = ERR_TO_LEGO_RET(ret);
		reply->line = __LINE__;
		return;
	}

	map_flags = MAP_FIXED;
	if (vma->vm_flags & VM_MAYSHARE)
		map_flags |= MAP_SHARED;

	/* Try to allocate this new virtual address range */
	ret = get_unmapped_area(tsk, vma->vm_file, new_addr, new_len, vma->vm_pgoff +
				((addr - vma->vm_start) >> PAGE_SHIFT), map_flags);
	if (offset_in_page(ret)) {
		reply->status = RET_ENOMEM;
		reply->line = __LINE__;
		return;
	}

	ret = move_vma(tsk, vma, addr, old_len, new_len, new_addr);
	if (offset_in_page(ret)) {
		reply->status = RET_ENOMEM;
		reply->line = __LINE__;
		return;
	}

	/* Finally! */
	reply->status = RET_OKAY;
	reply->new_addr = new_addr;
}

static int vma_expandable(struct lego_task_struct *tsk,
			  struct vm_area_struct *vma, unsigned long delta)
{
	unsigned long end = vma->vm_end + delta;
	if (end < vma->vm_end) /* overflow */
		return 0;
	if (vma->vm_next && vma->vm_next->vm_start < end) /* intersection */
		return 0;
	if (get_unmapped_area(tsk, NULL, vma->vm_start, end - vma->vm_start,
			      0, MAP_FIXED) & ~PAGE_MASK)
		return 0;
	return 1;
}

int handle_p2m_mremap(struct p2m_mremap_struct *payload, u64 desc,
		      struct common_header *hdr)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	u64 addr = payload->addr;
	u64 old_len = payload->old_len;
	u64 new_len = payload->new_len;
	u64 flags = payload->flags;
	u64 new_addr = payload->new_addr;
	struct lego_task_struct *tsk;
	struct vm_area_struct *vma;
	struct p2m_mremap_reply_struct reply;
	unsigned long ret;

	mmap_debug("nid:%u,pid:%u,addr:%#Lx,old_len:%#Lx,new_len:%#Lx,"
		   "flags:%#Lx,new_addr:%#Lx", nid, pid, addr, old_len,
		   new_len, flags, new_addr);

	tsk = find_lego_task_by_pid(nid, pid);
	if (unlikely(!tsk)) {
		reply.status = RET_ESRCH;
		reply.line = __LINE__;
		goto out_nolock;
	}
	debug_dump_vm_all(tsk->mm, 1);

	if (down_write_killable(&tsk->mm->mmap_sem)) {
		reply.status = RET_EINTR;
		reply.line = __LINE__;
		goto out_nolock;
	}

	if (flags & MREMAP_FIXED) {
		mremap_to(addr, old_len, new_addr, new_len, tsk, &reply);
		goto out;
	}

	/*
	 * Always allow a shrinking remap: that just unmaps
	 * the unnecessary pages..
	 * do_munmap does all the needed commit accounting
	 */
	if (old_len >= new_len) {
		ret = do_munmap(tsk->mm, addr + new_len, old_len - new_len);
		if (ret && old_len != new_len) {
			reply.status = ERR_TO_LEGO_RET(ret);
			reply.line = __LINE__;
			goto out;
		}

		/* Succeed */
		reply.status = RET_OKAY;
		reply.new_addr = addr;
		goto out;
	}

	/* Ok, we need to grow.. */
	vma = vma_to_resize(addr, old_len, new_len, tsk);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		reply.status = ERR_TO_LEGO_RET(ret);
		reply.line = __LINE__;
		goto out;
	}

	/* old_len exactly to the end of the area.. */
	if (old_len == vma->vm_end - addr) {
		/* can we just expand the current mapping? */
		if (vma_expandable(tsk, vma, new_len - old_len)) {
			if (vma_adjust(vma, vma->vm_start, addr + new_len,
				       vma->vm_pgoff, NULL)) {
				reply.status = RET_ENOMEM;
				reply.line = __LINE__;
				goto out;
			}

			/* Succeed */
			reply.status = RET_OKAY;
			reply.new_addr = addr;
			goto out;
		}
	}

	/*
	 * We weren't able to just expand or shrink the area,
	 * we need to create a new one and move it..
	 */
	if (flags & MREMAP_MAYMOVE) {
		unsigned long map_flags = 0;
		if (vma->vm_flags & VM_MAYSHARE)
			map_flags |= MAP_SHARED;

		new_addr = get_unmapped_area(tsk, vma->vm_file, 0, new_len,
					vma->vm_pgoff +
					((addr - vma->vm_start) >> PAGE_SHIFT),
					map_flags);
		if (offset_in_page(new_addr)) {
			ret = new_addr;
			reply.status = ERR_TO_LEGO_RET(ret);
			reply.line = __LINE__;
			goto out;
		}

		ret = move_vma(tsk, vma, addr, old_len, new_len, new_addr);
		if (offset_in_page(ret)) {
			reply.status = ERR_TO_LEGO_RET(ret);
			reply.line = __LINE__;
			goto out;
		} else {
			/* Succeed */
			reply.status = RET_OKAY;
			reply.new_addr = ret;
			goto out;
		}
	} else {
		reply.status = RET_EINVAL;
		reply.line = __LINE__;
	}

out:
	up_write(&tsk->mm->mmap_sem);

out_nolock:
	mmap_debug("status: %s, new_addr: %#Lx, line: %u",
		ret_to_string(reply.status), reply.new_addr,
		(reply.status != RET_OKAY) ? reply.line : 0);

	ibapi_reply_message(&reply, sizeof(reply), desc);
	debug_dump_vm_all(tsk->mm, 0);
	return 0;
}

int handle_p2m_mprotect(struct p2m_mprotect_struct *payload, u64 desc,
			struct common_header *hdr)
{
	WARN_ON(1);
	return 0;
}
