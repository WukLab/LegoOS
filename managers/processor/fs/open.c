/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/stat.h>
#include <lego/slab.h>
#include <lego/uaccess.h>
#include <lego/files.h>
#include <lego/syscalls.h>
#include <lego/spinlock.h>
#include <lego/comp_processor.h>

#include "internal.h"

/*
 * Find @file by @fd
 * If file is found, we increment 1 ref
 */
struct file *fdget(int fd)
{
	struct files_struct *files = current->files;
	struct file *filp = NULL;

	spin_lock(&files->file_lock);
	if (likely(test_bit(fd, files->fd_bitmap))) {
		filp = files->fd_array[fd];
		BUG_ON(!filp);
		get_file(filp);
	}
	spin_unlock(&files->file_lock);

	return filp;
}

/**
 * Allocate a file structure and init it.
 * The returned @file already has ref set to 1
 */
static struct file *alloc_file(char *f_name)
{
	struct file *filp;

	filp = kmalloc(sizeof(*filp), GFP_KERNEL);
	if (filp) {
		atomic_set(&filp->f_count, 1);
		spin_lock_init(&filp->f_pos_lock);
		strncpy(filp->f_name, f_name, FILENAME_LEN_DEFAULT);
	}
	return filp;
}

/*
 * Allocate both fd and struct file
 * This should be called only from sys_open()
 */
static int alloc_fd(struct files_struct *files, char *filename)
{
	int fd;
	struct file *filp;

	spin_lock(&files->file_lock);
	for_each_clear_bit(fd, files->fd_bitmap, NR_OPEN_DEFAULT) {
		BUG_ON(files->fd_array[fd]);
		filp = alloc_file(filename);
		if (likely(filp)) {
			__set_bit(fd, files->fd_bitmap);
			files->fd_array[fd] = filp;
			spin_unlock(&files->file_lock);
			return fd;
		}
	}
	spin_unlock(&files->file_lock);

	return -EMFILE;
}

SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
	char kname[FILENAME_LEN_DEFAULT];
	int fd;

	debug_syscall_print();

	if (strncpy_from_user(kname, filename, FILENAME_LEN_DEFAULT) < 0)
		return -EFAULT;

	/*
	 * Allocate fd and struct file
	 * and @file has ref set to 1 if succeed
	 */
	fd = alloc_fd(current->files, kname);
	return fd;
}

SYSCALL_DEFINE1(close, unsigned int, fd)
{
	debug_syscall_print();
	pr_info("%s(): fd: %d\n", __func__, fd);
	return -EFAULT;
}

SYSCALL_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd)
{
	debug_syscall_print();
	pr_info("%s(): oldfd: %u newfd: %u\n",
		__func__, oldfd, newfd);
	return -EFAULT;
}

SYSCALL_DEFINE1(dup, unsigned int, fildes)
{
	debug_syscall_print();
	pr_info("%s(): fildes: %u\n", __func__, fildes);
	return -EFAULT;
}
