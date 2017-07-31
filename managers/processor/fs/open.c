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

static void free_fd(struct files_struct *files, int fd)
{
	struct file *f;

	spin_lock(&files->file_lock);
	if (likely(test_bit(fd, files->fd_bitmap))) {
		f = files->fd_array[fd];
		BUG_ON(!f);

		put_file(f);
		__clear_bit(fd, files->fd_bitmap);
		files->fd_array[fd] = NULL;
	}
	spin_unlock(&files->file_lock);
}

SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
	char kname[FILENAME_LEN_DEFAULT];
	int fd, ret;
	struct file *f;

	syscall_enter();

	if (strncpy_from_user(kname, filename, FILENAME_LEN_DEFAULT) < 0) {
		fd = -EFAULT;
		goto out;
	}

	/*
	 * Allocate fd and struct file
	 * and @file has ref set to 1 if succeed
	 */
	fd = alloc_fd(current->files, kname);
	if (unlikely(fd < 0))
		goto out;

	f = fdget(fd);
	if (unlikely(proc_file(kname)))
		ret = proc_file_open(f, kname);
	else if (unlikely(sys_file(kname)))
		ret = sys_file_open(f, kname);
	else
		ret = normal_file_open(f, kname);

	if (unlikely(ret)) {
		free_fd(current->files, fd);
		fd = ret;
		goto put;
	}

	BUG_ON(!f->f_op->open);
	ret = f->f_op->open(f);
	if (unlikely(ret)) {
		free_fd(current->files, fd);
		fd = ret;
	}

put:
	pr_info("%s(): [%d] -> [%s]\n", __func__, fd, filename);
	put_file(f);
out:
	syscall_exit(fd);
	return fd;
}

SYSCALL_DEFINE1(close, unsigned int, fd)
{
	struct file *f = NULL;
	struct files_struct *files = current->files;
	int ret;

	syscall_enter();

	spin_lock(&files->file_lock);
	if (likely(test_bit(fd, files->fd_bitmap))) {
		f = files->fd_array[fd];
		BUG_ON(!f);

		if (f->f_op->release)
			f->f_op->release(f);
		put_file(f);
		__clear_bit(fd, files->fd_bitmap);
		files->fd_array[fd] = NULL;

		ret = 0;
	} else {
		ret = -EBADF;
	}
	spin_unlock(&files->file_lock);

	pr_info("%s(): [%d] -> [%s]\n", __func__, fd,
		f ? f->f_name : "-EBADF");

	syscall_exit(ret);
	return ret;
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
