/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/vm-pgtable.h>
#include <memory/file_ops.h>
#include <memory/distvm.h>
#include <memory/replica.h>
#include <memory/thread_pool.h>

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
#ifndef CONFIG_DISTRIBUTED_VMA_MEMORY
void handle_p2m_brk(struct p2m_brk_struct *payload,
		    struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	unsigned long min_brk, brk = payload->brk;
	unsigned long newbrk, oldbrk;
	struct lego_task_struct *tsk;
	struct lego_mm_struct *mm;
	struct p2m_brk_reply_struct *reply;
	int ret;

	mmap_debug("src_nid: %u, pid: %u, brk: %#lx", nid, pid, brk);

	reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	tsk = find_lego_task_by_pid(nid, pid);
	if (unlikely(!tsk)) {
		reply->ret_brk = RET_ESRCH;
		return;
	}
	debug_dump_vm_all(tsk->mm, 1);

	mm = tsk->mm;
	if (down_write_killable(&mm->mmap_sem)) {
		reply->ret_brk = RET_EINTR;
		return;
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

	reply->ret_brk = mm->brk;

	replicate_vma(tsk, REPLICATE_BRK, newbrk, 0, oldbrk, 0);
	debug_dump_vm_all(mm, 0);
}
#endif

/**
 * Returns: the virtual address
 *  ERROR:
 *	RET_ESRCH
 */
void handle_p2m_mmap(struct p2m_mmap_struct *payload,
		     struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	unsigned long addr = payload->addr;
	unsigned long len = payload->len;
	unsigned long prot = payload->prot;
	unsigned long flags = payload->flags;
	unsigned long pgoff = payload->pgoff;
	char *f_name = payload->f_name;
	struct lego_task_struct *tsk;
	struct lego_file *file = NULL;
	struct p2m_mmap_reply_struct *reply;
	s64 ret;

	mmap_debug("src_nid:%u,pid:%u,addr:%#lx,len:%#lx,prot:%#lx,flags:%#lx"
		   "pgoff:%#lx,f_name:[%s]", nid, pid, addr, len, prot,
		   flags, pgoff, f_name);

	reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	tsk = find_lego_task_by_pid(nid, pid);
	if (unlikely(!tsk)) {
		reply->ret = -ESRCH;
		return;
	}
	debug_dump_vm_all(tsk->mm, 1);

	/*
	 * Are we doing a file-backed mmap()?
	 * If so, we need to allocate a lego_file to attach to this vma:
	 */
	if (!(flags & MAP_ANONYMOUS)) {
		file = file_open(tsk, f_name);
		if (IS_ERR(file)) {
			reply->ret = -ENOMEM;
			return;
		}
	}

	flags &= ~(MAP_EXECUTABLE | MAP_DENYWRITE);

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	if (down_write_killable(&tsk->mm->mmap_sem)) {
		reply->ret = -EINTR;
		return;
	}

	load_reply_buffer(tsk->mm, &(reply->map));
	ret = distvm_mmap_homenode(tsk->mm, file, addr, len, prot, flags, pgoff);
	remove_reply_buffer(tsk->mm);

	up_write(&tsk->mm->mmap_sem);
#else
	ret = vm_mmap_pgoff(tsk, file, addr, len, prot, flags, pgoff);
#endif

	/* which means vm_mmap_pgoff() returns -ERROR */
	if (unlikely(ret < 0)) {
		reply->ret = ret;
		return;
	}

	reply->ret = 0;
	reply->ret_addr = (unsigned long)ret;

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	dump_reply(&reply->map);
#endif

	replicate_vma(tsk, REPLICATE_MMAP, reply->ret_addr, len, 0, 0);
	debug_dump_vm_all(tsk->mm, 0);
}

void handle_p2m_munmap(struct p2m_munmap_struct *payload,
		       struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	unsigned long addr = payload->addr;
	unsigned long len = payload->len;
	struct lego_task_struct *tsk;
	struct lego_mm_struct *mm;
	struct p2m_munmap_reply_struct *reply;

	mmap_debug("src_nid:%u, pid:%u, addr:%#lx, len:%#lx",
		   nid, pid, addr, len);

	reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	tsk = find_lego_task_by_pid(nid, pid);
	if (unlikely(!tsk)) {
		reply->ret = RET_ESRCH;
		return;
	}
	debug_dump_vm_all(tsk->mm, 1);

	mm = tsk->mm;
	if (down_write_killable(&mm->mmap_sem)) {
		reply->ret = RET_EINTR;
		return;
	}

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	load_reply_buffer(tsk->mm, &reply->map);
	reply->ret = distvm_munmap_homenode(mm, addr, len);
	remove_reply_buffer(tsk->mm);
#else
	reply->ret = do_munmap(mm, addr, len);
#endif
	up_write(&mm->mmap_sem);

	replicate_vma(tsk, REPLICATE_MUNMAP, addr, len, 0, 0);
	debug_dump_vm_all(tsk->mm, 0);
}

static int do_msync(struct lego_mm_struct *mm, unsigned long start,
		    unsigned long end, unsigned long flags)
{
	int ret = 0, unmapped_error = 0;
	struct vm_area_struct *vma;

	/*
	 * If the interval [start,end) covers some unmapped address ranges,
	 * just ignore them, but return -ENOMEM at the end.
	 */
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
	return ret;
}

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
static int
distribute_msync(struct lego_task_struct *tsk, unsigned long start,
		 unsigned long len, unsigned long flags, int mnode)
{
	int ret, reply;
	struct m2m_msync_struct info;

	info.pid = tsk->pid;
	info.prcsr_nid = tsk->node;
	info.start = start;
	info.len = len;
	info.flags = flags;

	ret = net_send_reply_timeout(mnode, M2M_MSYNC, (void *)&info,
			sizeof(struct m2m_msync_struct), (void *)&reply,
			sizeof(int), false, FIT_MAX_TIMEOUT_SEC);

	if (ret < 0)
		return ret;

	return reply;
}

void handle_m2m_msync(struct m2m_msync_struct *payload,
		      struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	u32 prcsr_nid = payload->prcsr_nid;
	unsigned long start = payload->start;
	unsigned long len = payload->len;
	unsigned long flags = payload->flags;
	struct lego_task_struct *tsk;
	u32 *ret;

	mmap_debug("src_nid:%u,pid:%u,start:%#lx,len:%#lx,flags:%#lx",
		   nid, pid, start, len, flags);

	ret = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*ret));

	tsk = find_lego_task_by_pid(prcsr_nid, pid);
	if (unlikely(!tsk)) {
		*ret = RET_ESRCH;
		return;
	}
	debug_dump_vm_all(tsk->mm, 1);

	*ret = do_msync(tsk->mm, start, start + len, flags);

	debug_dump_vm_all(tsk->mm, 0);
}
#endif

int handle_p2m_msync(struct p2m_msync_struct *payload, u64 desc,
		     struct common_header *hdr, void *tx)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	unsigned long start = payload->start;
	unsigned long len = payload->len;
	unsigned long flags = payload->flags;
	struct lego_task_struct *tsk;
	u32 *ret = tx;
	*ret = 0;

	mmap_debug("src_nid:%u,pid:%u,start:%#lx,len:%#lx,flags:%#lx",
		   nid, pid, start, len, flags);

	tsk = find_lego_task_by_pid(nid, pid);
	if (unlikely(!tsk)) {
		*ret = RET_ESRCH;
		goto out;
	}
	debug_dump_vm_all(tsk->mm, 1);

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	while (len) {
		struct vma_tree *root;
		unsigned long end, delta = 0;

		root = tsk->mm->vmrange_map[vmr_idx(start)];
		end = min((unsigned long)root->end, start + len);
		delta = end - start;

		if (is_local(root->mnode))
			*ret |= do_msync(tsk->mm, start, end, flags);
		else
			*ret |= distribute_msync(tsk, start, end,
						flags, root->mnode);

		len -= delta;
		start += delta;
		VMA_BUG_ON(start + len > payload->start + payload->len);
	}
#else
	*ret = do_msync(tsk->mm, start, start + len, flags);
#endif

out:
	ibapi_reply_message(ret, sizeof(u32), desc);
	debug_dump_vm_all(tsk->mm, 0);
	return 0;
}

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
void handle_p2m_mremap(struct p2m_mremap_struct *payload,
		       struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	unsigned long old_addr = payload->old_addr;
	unsigned long old_len = payload->old_len;
	unsigned long new_len = payload->new_len;
	unsigned long flags = payload->flags;
	unsigned long new_addr = payload->new_addr;
	struct lego_task_struct *tsk;
	struct p2m_mremap_reply_struct *reply;

	mmap_debug("nid:%u,pid:%u,old_addr:%#lx,old_len:%#lx,new_len:%#lx,"
		   "flags:%#lx,new_addr:%#lx", nid, pid, old_addr, old_len,
		   new_len, flags, new_addr);

	reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	tsk = find_lego_task_by_pid(nid, pid);
	if (unlikely(!tsk)) {
		reply->status = RET_ESRCH;
		reply->line = __LINE__;
		return;
	}
	debug_dump_vm_all(tsk->mm, 1);

	if (down_write_killable(&tsk->mm->mmap_sem)) {
		reply->status = RET_EINTR;
		reply->line = __LINE__;
		return;
	}

	load_reply_buffer(tsk->mm, &reply->map);
	reply->new_addr = distvm_mremap_homenode(tsk->mm, old_addr, old_len,
						new_len, flags, new_addr);
	remove_reply_buffer(tsk->mm);

	if (IS_ERR_VALUE(reply->new_addr)) {
		reply->status = (__u32)reply->new_addr;
		goto out;
	}
	reply->status = 0;

	up_write(&tsk->mm->mmap_sem);

out:
	mmap_debug("status: %s, new_addr: %#Lx, line: %u",
		   ret_to_string(reply->status), reply->new_addr,
		   (reply->status != RET_OKAY) ? reply->line : 0);
	dump_reply(&reply->map);

	debug_dump_vm_all(tsk->mm, 0);
}
#else
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
	 *	old_len <= new_len
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
	ret = get_unmapped_area(tsk, vma->vm_file, new_addr, new_len,
			vma->vm_pgoff + ((addr - vma->vm_start) >> PAGE_SHIFT),
			map_flags);
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

void handle_p2m_mremap(struct p2m_mremap_struct *payload,
		       struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	unsigned long old_addr = payload->old_addr;
	unsigned long old_len = payload->old_len;
	unsigned long new_len = payload->new_len;
	unsigned long flags = payload->flags;
	unsigned long new_addr = payload->new_addr;
	struct lego_task_struct *tsk;
	struct vm_area_struct *vma;
	struct p2m_mremap_reply_struct *reply;
	unsigned long ret;

	mmap_debug("nid:%u,pid:%u,old_addr:%#lx,old_len:%#lx,new_len:%#lx,"
		   "flags:%#lx,new_addr:%#lx", nid, pid, old_addr, old_len,
		   new_len, flags, new_addr);

	reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	tsk = find_lego_task_by_pid(nid, pid);
	if (unlikely(!tsk)) {
		reply->status = RET_ESRCH;
		reply->line = __LINE__;
		return;
	}
	debug_dump_vm_all(tsk->mm, 1);

	if (down_write_killable(&tsk->mm->mmap_sem)) {
		reply->status = RET_EINTR;
		reply->line = __LINE__;
		return;
	}

	if (flags & MREMAP_FIXED) {
		mremap_to(old_addr, old_len, new_addr, new_len, tsk, reply);
		goto out;
	}
	/*
	 * Always allow a shrinking remap: that just unmaps
	 * the unnecessary pages..
	 * do_munmap does all the needed commit accounting
	 */
	if (old_len >= new_len) {
		ret = do_munmap(tsk->mm, old_addr + new_len, old_len - new_len);
		if (ret && old_len != new_len) {
			reply->status = ERR_TO_LEGO_RET(ret);
			reply->line = __LINE__;
			goto out;
		}

		/* Succeed */
		reply->status = RET_OKAY;
		reply->new_addr = old_addr;
		goto out;
	}

	/* Ok, we need to grow.. */
	vma = vma_to_resize(old_addr, old_len, new_len, tsk);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		reply->status = ERR_TO_LEGO_RET(ret);
		reply->line = __LINE__;
		goto out;
	}

	/* old_len exactly to the end of the area.. */
	if (old_len == vma->vm_end - old_addr) {
		/* can we just expand the current mapping? */
		if (vma_expandable(tsk, vma, new_len - old_len)) {
			if (vma_adjust(vma, vma->vm_start, old_addr + new_len,
				       vma->vm_pgoff, NULL)) {
				reply->status = RET_ENOMEM;
				reply->line = __LINE__;
				goto out;
			}

			/* Succeed */
			reply->status = RET_OKAY;
			reply->new_addr = old_addr;
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
				((old_addr - vma->vm_start) >> PAGE_SHIFT),
				map_flags);
		if (offset_in_page(new_addr)) {
			ret = new_addr;
			reply->status = ERR_TO_LEGO_RET(ret);
			reply->line = __LINE__;
			goto out;
		}

		ret = move_vma(tsk, vma, old_addr, old_len, new_len, new_addr);
		if (offset_in_page(ret)) {
			reply->status = ERR_TO_LEGO_RET(ret);
			reply->line = __LINE__;
			goto out;
		} else {
			/* Succeed */
			reply->status = RET_OKAY;
			reply->new_addr = ret;
			goto out;
		}
	} else {
		reply->status = RET_EINVAL;
		reply->line = __LINE__;
	}

out:
	up_write(&tsk->mm->mmap_sem);

	mmap_debug("status: %s, new_addr: %#Lx, line: %u",
		   ret_to_string(reply->status), reply->new_addr,
		   (reply->status != RET_OKAY) ? reply->line : 0);

	replicate_vma(tsk, REPLICATE_MREMAP, reply->new_addr, new_len, old_addr, old_len);
	debug_dump_vm_all(tsk->mm, 0);
}
#endif /* CONFIG_DISTRIBUTED_VMA_MEMORY */

void handle_p2m_mprotect(struct p2m_mprotect_struct *payload,
			 struct thpool_buffer *tb)
{
	int *reply = thpool_buffer_tx(tb);
	*reply = 0;
	tb_set_tx_size(tb, sizeof(*reply));
}

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
void handle_p2m_brk(struct p2m_brk_struct *payload,
		    struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	unsigned long min_brk, brk = payload->brk;
	unsigned long newbrk, oldbrk;
	struct lego_task_struct *tsk;
	struct lego_mm_struct *mm;
	struct p2m_brk_reply_struct *reply;
	int ret;

	mmap_debug("src_nid: %u, pid: %u, brk: %#lx", nid, pid, brk);

	reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	tsk = find_lego_task_by_pid(nid, pid);
	if (unlikely(!tsk)) {
		reply->ret_brk = RET_ESRCH;
		return;
	}
	debug_dump_vm_all(tsk->mm, 1);

	mm = tsk->mm;
	if (down_write_killable(&mm->mmap_sem)) {
		reply->ret_brk = RET_EINTR;
		return;
	}

	load_reply_buffer(mm, &reply->map);

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
		ret = distvm_munmap_homenode(mm, newbrk, oldbrk - newbrk);
		if (likely(!ret))
			goto set_brk;
		goto out;
	}

	if (find_dist_vma_intersection(mm, oldbrk, newbrk+PAGE_SIZE))
		goto out;

	/* Ok, looks good - let it rip. */
	ret = distvm_brk_homenode(tsk->mm, oldbrk, newbrk-oldbrk);
	if (unlikely(ret < 0))
		goto out;

set_brk:
	mm->brk = brk;

	/* Yup, by default, we populate */
	if (newbrk > oldbrk)
		lego_mm_populate(mm, oldbrk, newbrk - oldbrk);

out:
	remove_reply_buffer(mm);
	up_write(&mm->mmap_sem);

#ifdef CONFIG_DEBUG_VMA
	dump_reply(&reply->map);
#endif
	reply->ret_brk = mm->brk;
}

void handle_m2m_mmap(struct m2m_mmap_struct *payload,
		     struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	u32 prcsr_nid = payload->prcsr_nid;
	unsigned long new_range = payload->new_range;
	unsigned long addr = payload->addr;
	unsigned long len = payload->len;
	unsigned long prot = payload->prot;
	unsigned long flags = payload->flags;
	vm_flags_t vm_flags = payload->vm_flags;
	unsigned long pgoff = payload->pgoff;
	char *f_name = payload->f_name;
	struct lego_task_struct *tsk;
	struct lego_file *file = NULL;
	struct m2m_mmap_reply_struct *reply;

	mmap_debug("src_nid:%u, pid:%u, addr: %lx, len: %lx, prot:%lx, flags:%lx, "
		   "vm_flags: %lx, pgoff:%#lx, f_name:[%s]", nid, pid, addr, len,
		   prot, flags, vm_flags, pgoff, f_name);

	reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	/*
	 * since it's not homenode, won't be able to find task struct
	 * for the first mmap to this node
	 */
	tsk = find_lego_task_by_pid(prcsr_nid, pid);
	if (!tsk) {
		tsk = alloc_lego_task_struct();
		if (unlikely(!tsk)) {
			reply->addr = -ENOMEM;
			return;
		}

		tsk->pid = pid;
		tsk->node = prcsr_nid;
		mem_set_memory_home_node(tsk, nid);

		tsk->mm = lego_mm_alloc(tsk, NULL);
		if (!tsk->mm) {
			free_lego_task_struct(tsk);
			reply->addr = -ENOMEM;
			return;
		}

		/* All done, insert into hashtable */
		reply->addr = ht_insert_lego_task(tsk);
		if (reply->addr) {
			lego_mmput(tsk->mm);
			free_lego_task_struct(tsk);

			/* Same process? */
			if (likely(reply->addr == -EEXIST))
				reply->addr = 0;
			return;
		}

		/* virtual memory map layout */
		arch_pick_mmap_layout(tsk->mm);
	}
	debug_dump_vm_all(tsk->mm, 1);

	/*
	 * Are we doing a file-backed mmap()?
	 * If so, we need to allocate a lego_file to attach to this vma:
	 */
	if (!(flags & MAP_ANONYMOUS)) {
		file = file_open(tsk, f_name);
		if (IS_ERR(file)) {
			reply->addr = -ENOMEM;
			return;
		}
	}

	if (down_write_killable(&tsk->mm->mmap_sem)) {
		reply->addr = -EINTR;
		return;
	}

	flags &= ~(MAP_EXECUTABLE | MAP_DENYWRITE);
	reply->addr = do_dist_mmap(tsk->mm, file, LEGO_LOCAL_NID, new_range, addr, len,
				  prot, flags, vm_flags, pgoff, &reply->max_gap);

	up_write(&tsk->mm->mmap_sem);

	debug_dump_vm_all(tsk->mm, 0);
}

void handle_m2m_munmap(struct m2m_munmap_struct *payload,
		       struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	u32 prcsr_nid = payload->prcsr_nid;
	unsigned long begin = payload->begin;
	unsigned long len = payload->len;
	struct lego_task_struct *tsk;
	struct lego_mm_struct *mm;
	struct m2m_munmap_reply_struct *reply;

	mmap_debug("src_nid:%u, pid:%u, begin:%#lx, len:%#lx",
		   nid, pid, begin, len);

	reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	tsk = find_lego_task_by_pid(prcsr_nid, pid);
	if (unlikely(!tsk)) {
		reply->status = RET_ESRCH;
		return;
	}
	debug_dump_vm_all(tsk->mm, 1);

	mm = tsk->mm;
	if (down_write_killable(&mm->mmap_sem)) {
		reply->status = RET_EINTR;
		return;
	}

	reply->status = distvm_munmap(mm, begin, len, &reply->max_gap);
	up_write(&mm->mmap_sem);

	mmap_debug("%s, reply status: %x, max_gap: %lx\n",
			__func__, reply->status, reply->max_gap);
	debug_dump_vm_all(tsk->mm, 0);
}

void handle_m2m_findvma(struct m2m_findvma_struct *payload,
			struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	u32 prcsr_nid = payload->prcsr_nid;
	unsigned long begin = payload->begin;
	unsigned long end = payload->end;
	struct lego_task_struct *tsk;
	struct lego_mm_struct *mm;
	struct m2m_findvma_reply_struct *reply;
	struct vma_tree *root;

	mmap_debug("src_nid:%u, pid:%u, begin:%#lx, end:%#lx",
		   nid, pid, begin, end);

	reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	tsk = find_lego_task_by_pid(prcsr_nid, pid);
	if (unlikely(!tsk)) {
		reply->vma_exist = RET_ESRCH;
		return;
	}
	debug_dump_vm_all(tsk->mm, 1);

	mm = tsk->mm;
	if (down_write_killable(&mm->mmap_sem)) {
		reply->vma_exist = RET_EINTR;
		return;
	}

	reply->vma_exist = 0;
	root = mm->vmrange_map[last_vmr_idx(end)];
	load_vma_context(mm, root);
	if (find_vma_intersection(mm, begin, end))
		reply->vma_exist = 1;
	save_vma_context(mm, root);
	up_write(&mm->mmap_sem);

	debug_dump_vm_all(tsk->mm, 0);
}

void handle_m2m_mremap_grow(struct m2m_mremap_grow_struct *payload,
			    struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	u32 prcsr_nid = payload->prcsr_nid;
	unsigned long addr = payload->addr;
	unsigned long old_len = payload->old_len;
	unsigned long new_len = payload->new_len;
	struct lego_task_struct *tsk;
	struct lego_mm_struct *mm;
	struct m2m_mremap_grow_reply_struct *reply;

	mmap_debug("src_nid:%u, pid:%u, addr:%#lx, old_len:%#lx, new_len:%#lx",
		   nid, pid, addr, old_len, new_len);

	reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	tsk = find_lego_task_by_pid(prcsr_nid, pid);
	if (unlikely(!tsk)) {
		reply->status = RET_ESRCH;
		return;
	}
	debug_dump_vm_all(tsk->mm, 1);

	mm = tsk->mm;
	if (down_write_killable(&mm->mmap_sem)) {
		reply->status = RET_EINTR;
		return;
	}

	reply->status = distvm_mremap_grow(tsk, addr, old_len, new_len);
	reply->max_gap = mm->vmrange_map[vmr_idx(addr)]->max_gap;

	up_write(&mm->mmap_sem);

	debug_dump_vm_all(tsk->mm, 0);
}

void handle_m2m_mremap_move(struct m2m_mremap_move_struct *payload,
			   struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	u32 prcsr_nid = payload->prcsr_nid;
	unsigned long old_addr = payload->old_addr;
	unsigned long old_len = payload->old_len;
	unsigned long new_len = payload->new_len;
	unsigned long new_range = payload->new_range;
	struct lego_task_struct *tsk;
	struct lego_mm_struct *mm;
	struct m2m_mremap_move_reply_struct *reply;

	mmap_debug("src_nid:%u, pid:%u, old_addr:%#lx, old_len:%#lx, "
		   "new_len:%#lx, new_range:%#lx",
		   nid, pid, old_addr, old_len, new_len, new_range);

	reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	tsk = find_lego_task_by_pid(prcsr_nid, pid);
	if (unlikely(!tsk)) {
		WARN_ON_ONCE(1);
		reply->new_addr = -ESRCH;
		return;
	}
	debug_dump_vm_all(tsk->mm, 1);

	mm = tsk->mm;
	if (down_write_killable(&mm->mmap_sem)) {
		WARN_ON_ONCE(1);
		reply->new_addr = -EINTR;
		return;
	}

	reply->new_addr = do_dist_mremap_move(mm, LEGO_LOCAL_NID, old_addr, old_len,
					new_len, new_range, &reply->old_max_gap,
					&reply->new_max_gap);
	up_write(&mm->mmap_sem);

	debug_dump_vm_all(tsk->mm, 0);
}

void handle_m2m_mremap_move_split(struct m2m_mremap_move_split_struct *payload,
				  struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	u32 prcsr_nid = payload->prcsr_nid;
	unsigned long old_addr = payload->old_addr;
	unsigned long old_len = payload->old_len;
	unsigned long new_addr = payload->new_addr;
	unsigned long new_len = payload->new_len;
	struct lego_task_struct *tsk;
	struct lego_mm_struct *mm;
	struct m2m_mremap_move_split_reply_struct *reply;

	mmap_debug("src_nid:%u, pid:%u, old_addr:%#lx, new_addr:&%lx, "
		   "old_len:%#lx, new_len:%#lx",
		   nid, pid, old_addr, new_addr, old_len, new_len);

	reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	tsk = find_lego_task_by_pid(prcsr_nid, pid);
	if (unlikely(!tsk)) {
		WARN_ON_ONCE(1);
		reply->new_addr = -ESRCH;
		return;
	}
	debug_dump_vm_all(tsk->mm, 1);

	mm = tsk->mm;
	if (down_write_killable(&mm->mmap_sem)) {
		WARN_ON_ONCE(1);
		reply->new_addr = -EINTR;
		return;
	}

	reply->new_addr = do_dist_mremap_move_split(mm, old_addr, old_len,
				new_addr, new_len, &reply->old_max_gap,
				&reply->new_max_gap);

	up_write(&mm->mmap_sem);

	debug_dump_vm_all(tsk->mm, 0);
}

#ifdef CONFIG_DEBUG_VMA
void handle_m2m_validate(struct m2m_validate_struct *payload,
			 struct common_header *hdr, struct thpool_buffer *tb)
{
	u32 nid = hdr->src_nid;
	u32 pid = payload->pid;
	u32 prcsr_nid = payload->prcsr_nid;
	unsigned long addr = payload->addr;
	unsigned long len = payload->len;
	struct lego_task_struct *tsk;
	struct lego_mm_struct *mm;
	int *reply;

	mmap_debug("src_nid:%u, pid:%u, addr:%#lx, len:&%lx, ",
		   nid, pid, addr, len);

	reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	tsk = find_lego_task_by_pid(prcsr_nid, pid);
	if (unlikely(!tsk)) {
		WARN_ON_ONCE(1);
		*reply = -ESRCH;
		return;
	}
	debug_dump_vm_all(tsk->mm, 1);

	mm = tsk->mm;
	if (down_write_killable(&mm->mmap_sem)) {
		WARN_ON_ONCE(1);
		*reply = -EINTR;
		return;
	}

	mmap_brk_validate_local(mm, addr, len);
	*reply = 0;

	up_write(&mm->mmap_sem);
	debug_dump_vm_all(tsk->mm, 0);
}
#endif

#endif /* CONFIG_DISTRIBUTED_VMA_MEMORY */
