/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Copy bytes to/from process virtual memory.
 * The basic idea is the same as original copy_to/from_user: make sure pages
 * are mapped before we do the copy. Instead of triggering real hardware pgfault,
 * we manually get_user_pages() first to make sure pages are mapped.
 *
 * This code looks a little complicated because the user virtual address would
 * map to non-contiguous kernel virtual address, so might need to copy one by one.
 */

#include <lego/slab.h>
#include <lego/kernel.h>
#include <memory/vm.h>

#ifdef CONFIG_DEBUG_VM_UACCESS
#define uaccess_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
static inline void uaccess_debug(const char *fmt, ...) { }
#endif

/*
 * Just used to catch potential bugs.
 * If any uaccess functions want to touch more than
 * this number of pages, we will inject a warning.
 */
#define UACCESS_WARNING_LIMIT	3

static __always_inline void
__lego_copy_to_user(void *to, const void *from, size_t len)
{
	uaccess_debug("    to_knl[%#lx-%#lx], from_knl[%#lx-%#lx] bytes=%zu",
		(unsigned long)to, (unsigned long)to + len - 1,
		(unsigned long)from, (unsigned long)from + len - 1,
		len);

	memcpy(to, from, len);
}

/**
 * lego_copy_to_user
 * @to: virtual address of user process
 * @from: virtual address of kernel
 * @n: number of bytes to copy
 *
 * Return bytes been copied, 0 on failure.
 */
unsigned long _lego_copy_to_user(struct lego_task_struct *tsk,
				 void __user *to, const void *from, size_t n,
				 const char *caller)
{
	unsigned long first_page, last_page, nr_pages;
	long ret;

	if (!n) {
		WARN_ON(1);
		return 0;
	}

	uaccess_debug("to_usr[%#lx-%#lx], bytes=%zu, caller: %s",
		(unsigned long)to, (unsigned long)to + n - 1, n, caller);

	if ((unsigned long)to > TASK_SIZE) {
		__lego_copy_to_user(to, from, n);
		return n;
	}

	first_page = (unsigned long)to & PAGE_MASK;
	last_page = ((unsigned long)to + n - 1) & PAGE_MASK;
	nr_pages = ((last_page - first_page) >> PAGE_SHIFT) + 1;

	/* this should be the normal case */
	if (likely(nr_pages == 1)) {
		unsigned long page;

		down_read(&tsk->mm->mmap_sem);
		ret = get_user_pages(tsk, first_page, 1, 0, &page, NULL);
		up_read(&tsk->mm->mmap_sem);
		if (unlikely(ret != 1))
			return 0;

		__lego_copy_to_user((void *)(page + offset_in_page(to)),
				    from, n);
		return n;
	} else {
	/* otherwise, it does not seem fast.. */
		unsigned long *pages;
		unsigned long bytes_to_copy, start, offset, copied = 0;
		int i;

		WARN_ON(nr_pages > UACCESS_WARNING_LIMIT);

		pages = kmalloc(sizeof(unsigned long) * nr_pages, GFP_KERNEL);
		if (unlikely(!pages))
			return 0;

		down_read(&tsk->mm->mmap_sem);
		ret = get_user_pages(tsk, first_page, nr_pages, 0, pages, NULL);
		up_read(&tsk->mm->mmap_sem);
		if (unlikely(ret != nr_pages)) {
			kfree(pages);
			return 0;
		}

		/* Copy one by one */
		start = (unsigned long)to;
		for (i = 0; i < nr_pages; i++) {
			offset = offset_in_page(start);

			bytes_to_copy = PAGE_SIZE - offset;

			/* last page case */
			if (bytes_to_copy >= (n - copied))
				bytes_to_copy = n - copied;

			__lego_copy_to_user((void *)(pages[i] + offset),
					    from + copied, bytes_to_copy);

			copied += bytes_to_copy;
			start += bytes_to_copy;
		}

		kfree(pages);
		return copied;
	}
	return 0;
}

static __always_inline void
__lego_copy_from_user(void *to, const void *from, size_t len)
{
	uaccess_debug("    to_knl[%#lx-%#lx], from_knl[%#lx-%#lx] bytes=%zu",
		(unsigned long)to, (unsigned long)to + len - 1,
		(unsigned long)from, (unsigned long)from + len - 1,
		len);

	memcpy(to, from, len);
}

/**
 * lego_copy_from_user
 * @to: virtual address of kernel
 * @from: virtual address of user process
 * @n: number of bytes to copy
 *
 * Return bytes been copied, 0 on failure.
 */
unsigned long _lego_copy_from_user(struct lego_task_struct *tsk,
				   void *to , const void __user *from, size_t n,
				   const char *caller)
{
	unsigned long first_page, last_page, nr_pages;
	long ret;

	if (!n) {
		WARN_ON(1);
		return 0;
	}

	uaccess_debug("from_usr[%#lx-%#lx], bytes=%zu, caller: %s",
		(unsigned long)from, (unsigned long)from + n - 1, n, caller);

	if ((unsigned long)from > TASK_SIZE) {
		__lego_copy_from_user(to, from, n);
		return n;
	}

	first_page = (unsigned long)from & PAGE_MASK;
	last_page = ((unsigned long)from + n - 1) & PAGE_MASK;
	nr_pages = ((last_page - first_page) >> PAGE_SHIFT) + 1;

	if (likely(nr_pages == 1)) {
		unsigned long page;

		down_read(&tsk->mm->mmap_sem);
		ret = get_user_pages(tsk, first_page, 1, 0, &page, NULL);
		up_read(&tsk->mm->mmap_sem);
		if (unlikely(ret != 1))
			return 0;

		__lego_copy_from_user(to, (void *)(page + offset_in_page(from)), n);
		return n;
	} else {
		unsigned long *pages;
		unsigned long bytes_to_copy, start, offset, copied = 0;
		int i;

		WARN_ON(nr_pages > UACCESS_WARNING_LIMIT);

		pages = kmalloc(sizeof(unsigned long) * nr_pages, GFP_KERNEL);
		if (unlikely(!pages))
			return 0;

		down_read(&tsk->mm->mmap_sem);
		ret = get_user_pages(tsk, first_page, nr_pages, 0, pages, NULL);
		up_read(&tsk->mm->mmap_sem);
		if (unlikely(ret != nr_pages)) {
			kfree(pages);
			return 0;
		}

		/* Copy one by one */
		start = (unsigned long)from;
		for (i = 0; i < nr_pages; i++) {
			offset = offset_in_page(start);

			bytes_to_copy = PAGE_SIZE - offset;

			/* last page case */
			if (bytes_to_copy >= (n - copied))
				bytes_to_copy = n - copied;

			__lego_copy_from_user(to + copied,
				(void *)(pages[i] + offset), bytes_to_copy);

			copied += bytes_to_copy;
			start += bytes_to_copy;
		}

		kfree(pages);
		return copied;
	}
	return 0;
}

/**
 * lego_clear_user: - Zero a block of memory in user space.
 * @to:   Destination address, in user space.
 * @n:    Number of bytes to zero.
 *
 * Zero a block of memory in user space.
 *
 * Returns number of bytes that could not be cleared.
 * On success, this will be zero.
 */
unsigned long _lego_clear_user(struct lego_task_struct *tsk,
			       void * __user dst, size_t cnt, const char *caller)
{
	char zero = 0;

	if (!cnt) {
		WARN_ON(1);
		return 0;
	}

	WARN_ON(cnt > UACCESS_WARNING_LIMIT * PAGE_SIZE);

	uaccess_debug("to_usr[%#lx-%#lx], bytes=%zu, caller: %s",
		(unsigned long)dst, (unsigned long)dst + cnt - 1, cnt, caller);

	while (cnt) {
		if (unlikely(!lego_copy_to_user(tsk, dst++, &zero, 1)))
			break;
		cnt--;
	}
	return cnt;
}
