/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Copy bytes to/from process virtual memory.
 * The basic idea is the same as original copy_to/from_user: make sure pages
 * are mapped before we do the copy.
 *
 * Instead of triggering real hardware pgfault, we manually get_user_pages()
 * first to make sure pages are mapped.
 */

#include <lego/slab.h>
#include <lego/kernel.h>
#include <memory/include/vm.h>

/**
 * @to: virtual address of user process
 * @from: virtual address of kernel
 * @n: number of bytes to copy
 *
 * Return bytes been copied, 0 on failure.
 */
unsigned long lego_copy_to_user(struct lego_task_struct *tsk,
				void __user *to, const void *from, size_t n)
{
	unsigned long first_page, last_page, nr_pages;
	long ret;

	if (!n)
		return 0;

	first_page = (unsigned long)to & PAGE_MASK;
	last_page = ((unsigned long)to + n) & PAGE_MASK;
	nr_pages = ((last_page - first_page) >> PAGE_SHIFT) + 1;

	/* this should be the normal case */
	if (likely(nr_pages == 1)) {
		unsigned long page;

		down_read(&tsk->mm->mmap_sem);
		ret = get_user_pages(tsk, first_page, 1, 0, &page, NULL);
		up_read(&tsk->mm->mmap_sem);
		if (unlikely(ret != 1))
			return 0;

		memcpy((void *)(page + offset_in_page(to)), from, n);
		return n;
	} else {
	/* otherwise, it does not seem fast.. */
		unsigned long *pages;
		unsigned long bytes_to_copy, start, offset, copied = 0;
		int i;

		/* set a reasonable value to catch potential bug */
		WARN_ON(nr_pages > 4);

		pages = kmalloc(sizeof(unsigned long) * nr_pages, GFP_KERNEL);
		if (unlikely(!pages))
			return 0;

		down_read(&tsk->mm->mmap_sem);
		ret = get_user_pages(tsk, first_page, nr_pages, 0, pages, NULL);
		up_read(&tsk->mm->mmap_sem);
		if (unlikely(ret != nr_pages))
			return 0;

		/* Copy one by one */
		start = (unsigned long)to;
		for (i = 0; i < nr_pages; i++) {
			offset = offset_in_page(start);

			bytes_to_copy = PAGE_SIZE - offset;

			/* last page case */
			if (bytes_to_copy >= (n - copied))
				bytes_to_copy = n - copied;

			memcpy((void *)(pages[i] + offset),
				from + copied, bytes_to_copy);

			copied += bytes_to_copy;
			start += bytes_to_copy;
		}
		return copied;
	}
	return 0;
}

/**
 * @to: virtual address of kernel
 * @from: virtual address of user process
 * @n: number of bytes to copy
 */
unsigned long lego_copy_from_user(struct lego_task_struct *tsk,
				void *to , const void __user *from, size_t n)
{
	return 0;
}
