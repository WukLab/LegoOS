/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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
#include <processor/fs.h>
#include <processor/processor.h>
#include <lego/fit_ibapi.h>

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

	filp = kzalloc(sizeof(*filp), GFP_KERNEL);
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
int alloc_fd(struct files_struct *files, char *filename)
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

void free_fd(struct files_struct *files, int fd)
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

#ifdef CONFIG_USE_RAMFS
static struct file_operations debug_ramfs_f_ops = {
};
#endif

SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
	char kname[FILENAME_LEN_DEFAULT];
	int fd, ret;
	struct file *f;

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
	f->f_flags = flags;
	f->f_mode = mode;

	/*
	 * Ugh.. Just a dirty workaround for the
	 * 	Everything is a file philosophy.
	 */
	if (unlikely(proc_file(kname)))
		ret = proc_file_open(f, kname);
	else if (unlikely(sys_file(kname)))
		ret = sys_file_open(f, kname);
	else if (unlikely(dev_file(kname)))
		ret = dev_file_open(f, kname);
	else {
#ifdef CONFIG_USE_RAMFS
		f->f_op = &debug_ramfs_f_ops;
		ret = 0;
#else
		ret = normal_file_open(f, kname);
#endif
	}

	if (unlikely(ret)) {
		free_fd(current->files, fd);
		fd = ret;
		goto put;
	}

	if (f->f_op->open) {
		ret = f->f_op->open(f);
		if (unlikely(ret)) {
			free_fd(current->files, fd);
			fd = ret;
		}
	}

put:
	put_file(f);
out:
	pr_info("%s() CPU%d PID:%d f_name: %s, flags: %x, mode: %x fd: %d\n",
		__func__, smp_processor_id(), current->pid, kname, flags, mode, fd);
	return fd;
}

SYSCALL_DEFINE1(close, unsigned int, fd)
{
	struct file *f = NULL;
	struct files_struct *files = current->files;
	int ret;

	syscall_enter("%u\n", fd);

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

	pr_info("%s() CPU%d PID:%d [fd: %d] -> [%s]\n",
		__func__, smp_processor_id(), current->pid,
		fd, f ? f->f_name : "-EBADF");

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
	struct file *f;
	long ret, fd;
	struct files_struct *files;

	syscall_enter("fildes: %u\n", fildes);

	f = fdget(fildes);
	if (!f) {
		ret = -EBADF;
		goto out;
	}

	files = current->files;
	spin_lock(&files->file_lock);
	for_each_clear_bit(fd, files->fd_bitmap, NR_OPEN_DEFAULT) {
		BUG_ON(files->fd_array[fd]);
		__set_bit(fd, files->fd_bitmap);

		/* above fdget held 1 ref for us */
		files->fd_array[fd] = f;
		break;
	}
	spin_unlock(&files->file_lock);

	if (likely(fd < NR_OPEN_DEFAULT))
		ret = fd;
	else
		ret = -EMFILE;

out:
	syscall_exit(ret);
	return ret;
}

#ifndef CONFIG_USE_RAMFS
/* 
 * p2s_access: get access permission from storage
 * @kname: string of absolute file path on storage component
 * @mode: access mode for permission check
 * return value: 0 on success, -errno on fail
 */
static int p2s_access(char *kname, int mode)
{
	int retval; 
	void *msg;
	u32 len_msg, *opcode;
	struct p2s_access_struct *payload;

	len_msg = sizeof(*opcode) + sizeof(*payload);
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	opcode = msg;
	*opcode = P2S_ACCESS;

	payload = msg + sizeof(*opcode);
	payload->mode = mode;
	strncpy(payload->filename, kname, MAX_FILENAME_LENGTH);

	ibapi_send_reply_imm(current_storage_home_node(), msg, len_msg,
			     &retval, sizeof(retval), false);

	kfree(msg);
	return retval;
}
#endif

SYSCALL_DEFINE2(access, const char __user *, filename, int, mode)
{
	char kname[FILENAME_LEN_DEFAULT];

	if (strncpy_from_user(kname, filename, FILENAME_LEN_DEFAULT) < 0)
		return -EFAULT;

	syscall_enter("f_name: %s, mode: %x\n", kname, mode);

	/* Now allowing these special access for simplicity */
	if (unlikely(proc_file(kname) || sys_file(kname) || dev_file(kname)))
		return 0;

#ifdef CONFIG_USE_RAMFS
	return 0;
#else
	return p2s_access(kname, mode);
#endif
}
