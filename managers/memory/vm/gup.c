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
#include <lego/kernel.h>
#include <memory/vm.h>

int faultin_page(struct vm_area_struct *vma, unsigned long start,
		 unsigned long flags, unsigned long *kvaddr)
{
	int ret;

	ret = handle_lego_mm_fault(vma, start, flags, kvaddr, NULL);
	if (ret & VM_FAULT_ERROR) {
		if (ret & VM_FAULT_OOM)
			return -ENOMEM;
		if (ret & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
			return -EFAULT;
		BUG();
	}
	return 0;
}

/*
 * Find the VFN of a given user virtual address.
 *
 * Return:
 *	positive VFN number if found
 *	0 if pgtable is not established yet
 */
unsigned long find_page(struct vm_area_struct *vma, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	unsigned long page;
	struct lego_mm_struct *mm = vma->vm_mm;

	pgd = lego_pgd_offset(mm, address);
	if (pgd_none(*pgd))
		return 0;

	pud = lego_pud_offset(pgd, address);
	if (pud_none(*pud))
		return 0;

	pmd = lego_pmd_offset(pud, address);
	if (pmd_none(*pmd))
		return 0;

	pte = lego_pte_offset(pmd, address);
	if (pte_none(*pte))
		return 0;

	/* extract vfn from pte */
	page = pte_val(*pte) & PTE_VFN_MASK;
	return page;
}

static __always_inline long
__get_user_pages(struct lego_task_struct *tsk, struct lego_mm_struct *mm,
		 unsigned long start, unsigned long nr_pages,
		 unsigned int gup_flags, unsigned long *pages,
		 struct vm_area_struct **vmas, int *nonblocking)
{
	long i = 0;
	struct vm_area_struct *vma = NULL;

	if (!nr_pages)
		return 0;

	do {
		unsigned long page;

		/* first iteration or cross vma bound */
		if (!vma || start >= vma->vm_end) {
			vma = find_extend_vma(mm, start);
			if (!vma)
				return i ? : -EFAULT;
		}

retry:
		page = find_page(vma, start);
		if (!page) {
			int ret;
			unsigned long flags = FAULT_FLAG_WRITE;

			ret = faultin_page(vma, start, flags, &page);
			if (likely(!ret))
				goto retry;
			else
				return i ? i : ret;
		}

		if (pages)
			pages[i] = page;
		if (vmas)
			vmas[i] = vma;

		i++;
		start += PAGE_SIZE;
		nr_pages--;
	} while (nr_pages);
	return i;
}

static __always_inline long
__get_user_pages_locked(struct lego_task_struct *tsk, struct lego_mm_struct *mm,
			unsigned long start, unsigned long nr_pages,
			unsigned long *pages, struct vm_area_struct **vmas,
			int *locked, bool notify_drop, unsigned int flags)
{
	long ret, pages_done;
	bool lock_dropped;

	if (locked) {
		/* if VM_FAULT_RETRY can be returned, vmas become invalid */
		BUG_ON(vmas);
		/* check caller initialized locked */
		BUG_ON(*locked != 1);
	}

	pages_done = 0;
	lock_dropped = false;
	for (;;) {
		ret = __get_user_pages(tsk, mm, start, nr_pages, flags, pages,
				       vmas, locked);
		if (!locked)
			/* VM_FAULT_RETRY couldn't trigger, bypass */
			return ret;

		/* VM_FAULT_RETRY cannot return errors */
		if (!*locked) {
			BUG_ON(ret < 0);
			BUG_ON(ret >= nr_pages);
		}

		if (!pages)
			/* If it's a prefault don't insist harder */
			return ret;

		if (ret > 0) {
			nr_pages -= ret;
			pages_done += ret;
			if (!nr_pages)
				break;
		}
		if (*locked) {
			/* VM_FAULT_RETRY didn't trigger */
			if (!pages_done)
				pages_done = ret;
			break;
		}
		/* VM_FAULT_RETRY triggered, so seek to the faulting offset */
		pages += ret;
		start += ret << PAGE_SHIFT;

		/*
		 * Repeat on the address that fired VM_FAULT_RETRY
		 * without FAULT_FLAG_ALLOW_RETRY but with
		 * FAULT_FLAG_TRIED.
		 */
		*locked = 1;
		lock_dropped = true;
		down_read(&mm->mmap_sem);
		ret = __get_user_pages(tsk, mm, start, 1, flags | FOLL_TRIED,
				       pages, NULL, NULL);
		if (ret != 1) {
			BUG_ON(ret > 1);
			if (!pages_done)
				pages_done = ret;
			break;
		}
		nr_pages--;
		pages_done++;
		if (!nr_pages)
			break;
		pages++;
		start += PAGE_SIZE;
	}
	if (notify_drop && lock_dropped && *locked) {
		/*
		 * We must let the caller know we temporarily dropped the lock
		 * and so the critical section protected by it was lost.
		 */
		up_read(&mm->mmap_sem);
		*locked = 0;
	}
	return pages_done;
}

/*
 * Same as get_user_pages_unlocked(...., FOLL_TOUCH) but it allows to
 * pass additional gup_flags as last parameter (like FOLL_HWPOISON).
 *
 * NOTE: here FOLL_TOUCH is not set implicitly and must be set by the
 * caller if required (just like with __get_user_pages). "FOLL_GET",
 * "FOLL_WRITE" and "FOLL_FORCE" are set implicitly as needed
 * according to the parameters "pages", "write", "force"
 * respectively.
 */
__always_inline long
__get_user_pages_unlocked(struct lego_task_struct *tsk, struct lego_mm_struct *mm,
			  unsigned long start, unsigned long nr_pages,
			  unsigned long *pages, unsigned int gup_flags)
{
	long ret;
	int locked = 1;

	down_read(&mm->mmap_sem);
	ret = __get_user_pages_locked(tsk, mm, start, nr_pages, pages, NULL,
				      &locked, false, gup_flags);
	if (locked)
		up_read(&mm->mmap_sem);
	return ret;
}

/*
 * get_user_pages_remote() - get user pages to memory
 * @tsk:	the task_struct to use for page fault accounting
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @gup_flags:	flags modifying lookup behaviour
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_pages long. Or NULL, if caller
 *		only intends to ensure the pages are faulted in.
 * @vmas:	array of pointers to vmas corresponding to each page.
 *		Or NULL if the caller does not require them.
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno.
 *
 * Must be called with mmap_sem held for read or write.
 *
 * get_user_pages walks a process's page tables and takes a reference to
 * each struct page that each user address corresponds to at a given
 * instant. That is, it takes the page that would be accessed if a user
 * thread accesses the given user virtual address at that instant.
 */
long get_user_pages(struct lego_task_struct *tsk, unsigned long start,
		    unsigned long nr_pages, unsigned int gup_flags,
		    unsigned long *pages, struct vm_area_struct **vmas)
{
	return __get_user_pages_locked(tsk, tsk->mm, start, nr_pages,
				       pages, vmas, NULL, false,
				       gup_flags | FOLL_TOUCH);
}

/**
 * populate_vma_page_range() -  populate a range of pages in the vma.
 * @vma:   target vma
 * @start: start address
 * @end:   end address
 *
 * return 0 on success, negative error code on error.
 *
 * vma->vm_mm->mmap_sem must be held.
 */
long populate_vma_page_range(struct vm_area_struct *vma,
			     unsigned long start, unsigned long end,
			     int *nonblocking)
{
	struct lego_mm_struct *mm = vma->vm_mm;
	struct lego_task_struct *tsk = mm->task;
	unsigned long nr_pages = (end - start) / PAGE_SIZE;
	int gup_flags;

	VM_BUG_ON(start & ~PAGE_MASK);
	VM_BUG_ON(end   & ~PAGE_MASK);
	VM_BUG_ON_VMA(start < vma->vm_start, vma);
	VM_BUG_ON_VMA(end   > vma->vm_end, vma);
	//VM_BUG_ON_MM(!rwsem_is_locked(&mm->mmap_sem), mm);

	gup_flags = FOLL_TOUCH | FOLL_POPULATE;

	/*
	 * We want to touch writable mappings with a write fault in order
	 * to break COW, except for shared mappings because these don't COW
	 * and we would not want to dirty them for nothing.
	 */
	if ((vma->vm_flags & (VM_WRITE | VM_SHARED)) == VM_WRITE)
		gup_flags |= FOLL_WRITE;

	/*
	 * We want mlock to succeed for regions that have any permissions
	 * other than PROT_NONE.
	 */
	if (vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC))
		gup_flags |= FOLL_FORCE;

	/*
	 * We made sure addr is within a VMA, so the following will
	 * not result in a stack expansion that recurses back here.
	 */
	return __get_user_pages(tsk, mm, start, nr_pages, gup_flags,
				NULL, NULL, nonblocking);
}

/*
 * __lego_mm_populate - populate pages within a range of address space.
 *
 * This is used to implement mlock() and the MAP_POPULATE / MAP_LOCKED mmap
 * flags. VMAs must be already marked with the desired vm_flags, and
 * mmap_sem must *not* be held.
 */
int __lego_mm_populate(struct lego_mm_struct *mm, unsigned long start,
		       unsigned long len, int ignore_errors)
{
	unsigned long end, nstart, nend;
	struct vm_area_struct *vma = NULL;
	int locked = 0;
	long ret = 0;

	VM_BUG_ON(start & ~PAGE_MASK);
	VM_BUG_ON(len != PAGE_ALIGN(len));
	end = start + len;

	for (nstart = start; nstart < end; nstart = nend) {
		/*
		 * We want to fault in pages for [nstart; end) address range.
		 * Find first corresponding VMA.
		 */
		if (!locked) {
			locked = 1;
			if (!down_read_trylock(&mm->mmap_sem))
				return -EINTR;
			vma = find_vma(mm, nstart);
		} else if (nstart >= vma->vm_end)
			vma = vma->vm_next;
		if (!vma || vma->vm_start >= end)
			break;
		/*
		 * Set [nstart; nend) to intersection of desired address
		 * range with the first VMA. Also, skip undesirable VMA types.
		 */
		nend = min(end, vma->vm_end);
		if (vma->vm_flags & (VM_IO | VM_PFNMAP))
			continue;
		if (nstart < vma->vm_start)
			nstart = vma->vm_start;
		/*
		 * Now fault in a range of pages. populate_vma_page_range()
		 * double checks the vma flags, so that it won't mlock pages
		 * if the vma was already munlocked.
		 */
		ret = populate_vma_page_range(vma, nstart, nend, &locked);
		if (ret < 0) {
			if (ignore_errors) {
				ret = 0;
				continue;	/* continue at next VMA */
			}
			break;
		}
		nend = nstart + ret * PAGE_SIZE;
		ret = 0;
	}
	if (locked)
		up_read(&mm->mmap_sem);
	return ret;	/* 0 or negative error code */
}
