/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/net.h>
#include <lego/stat.h>
#include <lego/slab.h>
#include <lego/uaccess.h>
#include <lego/files.h>
#include <lego/syscalls.h>
#include <lego/spinlock.h>
#include <lego/fit_ibapi.h>
#include <processor/fs.h>
#include <processor/processor.h>

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
			filp->fd = fd;
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

void do_close_on_exec(struct files_struct *files)
{
#if 0
	unsigned int fd;

	/* Check opened files */
	spin_lock(&files->file_lock);
	for_each_set_bit(fd, files->fd_bitmap, NR_OPEN_DEFAULT) {
		struct file *f = files->fd_array[fd];

		BUG_ON(!f);

		/*
		 * XXX:
		 * Do we need to callback to f->op->release?
		 */
		if (close_on_exec(fd, files)) {
			pr_info("%s %d-%s fd: %d f_name: %s\n",
				__func__, current->pid, current->comm, fd, f->f_name);

			put_file(f);
			__clear_bit(fd, files->fd_bitmap);
			files->fd_array[fd] = NULL;
		}
	}
	spin_unlock(&files->file_lock);
#endif
}

void set_close_on_exec(unsigned int fd, int flag)
{
	struct files_struct *files = current->files;

	spin_lock(&files->file_lock);
	if (flag)
		__set_close_on_exec(fd, files);
	else
		__clear_close_on_exec(fd, files);
	spin_unlock(&files->file_lock);
}

bool get_close_on_exec(unsigned int fd)
{
	struct files_struct *files = current->files;
	long ret;

	spin_lock(&files->file_lock);
	ret = close_on_exec(fd, files);
	spin_unlock(&files->file_lock);

	return ret;
}

#ifdef CONFIG_USE_RAMFS
static struct file_operations debug_ramfs_f_ops = {
};
#endif



static void check_double_dots(char* s){
	char temp[FILENAME_LEN_DEFAULT];
	
	int found = 1;
	int last_slash = -1;
	int len = strlen(s);
	int j;
	char *dots;
	memset(temp, 0, FILENAME_LEN_DEFAULT);
	while (found){
		found = 0;
		dots = strstr(s, "/..");
		if (!dots || dots - s > FILENAME_LEN_DEFAULT || dots - s < 0)
			break;
		found = 1;
		for (j = dots - s - 1; j >= 0; j--){
			if (s[j] == '/') 
			{
				last_slash = j;
				break;
			}
		}
		memcpy(temp, s, last_slash);
		memcpy(temp + last_slash, dots + 3, strlen(s) - last_slash - 3);
		memset(s, 0, FILENAME_LEN_DEFAULT);
		memcpy(s, temp, strlen(temp));
		memset(temp, 0, FILENAME_LEN_DEFAULT);
	}
}



/*
 * do_sys_open		- open for pathname as the relative path of dfd
 * @dfd: directory file descriptor to be severed as the base for relative path resolving
 * @pathname: relative path from dfd
 * @flags: open flags
 * @mode: create file with mode when O_CREAT flag is specified
 *
 * Return: fd, on success fd > 0, on fail, fd = errno
 */
static long do_sys_open(int dfd, const char __user *pathname, int flags, umode_t mode)
{
	
	
	
	char kname[FILENAME_LEN_DEFAULT];
	int fd, ret;
	struct file *f;

	pr_info("Starting `do_sys_open`\n");

	fd = get_absolute_pathname(dfd, kname, pathname);
	if (unlikely(fd < 0))
		goto out;
	pr_info("Getting abs pathname %s from relative pathname %s\n", kname, pathname);
	check_double_dots(kname);
	pr_info("After earsing .., kname = %s\n", kname);
	/*
	 * Allocate fd and struct file
	 * and @file has ref set to 1 if succeed
	 */
	fd = alloc_fd(current->files, kname);

	pr_info("Fd allocated = %d\n", fd);
	if (unlikely(fd < 0))
		goto out;

	f = fdget(fd);
	f->f_flags = flags;
	f->f_mode = mode;

	/*
	 * poll and epoll init
	 * XXX: should be done inside socket_file_open()
	 */
#ifdef CONFIG_EPOLL
	INIT_LIST_HEAD(&f->f_epi_links);
#endif
	INIT_LIST_HEAD(&f->f_poll_links);
	f->ready_size = 0;
	f->ready_state = 0;

	/*
	 * Ugh.. Just a dirty workaround for the
	 * 	Everything is a file philosophy.
	 * We currently emulate:
	 *  - /proc
	 *  - /sys
	 *  - /dev
	 *  - socket
	 */
	if (unlikely(proc_file(kname)))
	{
		ret = proc_file_open(f, kname);
		pr_info("proc_file\n");
	}
	else if (unlikely(sys_file(kname)))
		{ret = sys_file_open(f, kname);
		pr_info("sys_file\n");}
	else if (unlikely(dev_file(kname)))
		{ret = dev_file_open(f, kname);
		pr_info("dev_file\n");}
	else if (unlikely(socket_file(kname)))
		{ret = socket_file_open(f); pr_info("socket_file\n");}
	else {
#ifdef CONFIG_USE_RAMFS
		f->f_op = &debug_ramfs_f_ops;
		ret = 0;
#else
		ret = default_file_open(f, kname);
		pr_info("default_file\n");
#endif
	}

	pr_info("ret of file open = %d\n", ret);

	if (unlikely(ret)) {
		free_fd(current->files, fd);
		fd = ret;
		goto put;
	}

	if (f->f_op->open) {
		
		ret = f->f_op->open(f);
		pr_info("ret of f_op_open = %d\n", ret);
		if (unlikely(ret)) {
			free_fd(current->files, fd);
			fd = ret;
		}
	}

pr_info("flags = %x\n", flags);

	if (flags & O_CLOEXEC)
		__set_close_on_exec(fd, current->files);
	else
		__clear_close_on_exec(fd, current->files);
put:
	pr_info("put file start\n");
	put_file(f);
	pr_info("put file success\n");
out:
	return fd;
}

SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
	long fd;

	syscall_filename(filename);
	syscall_enter("flags: %x, mode: %x\n", flags, mode);

	flags |= O_LARGEFILE;
	fd = do_sys_open(AT_FDCWD, filename, flags, mode);

	syscall_exit(fd);
	return fd;
}

SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename,
		int, flags, umode_t, mode)
{
	long fd;

	syscall_filename(filename);
	syscall_enter("dfd: %d, flags: %x, mode: %x\n", dfd, flags, mode);

	flags |= O_LARGEFILE;
	fd = do_sys_open(dfd, filename, flags, mode);

	syscall_exit(fd);
	return fd;
}

SYSCALL_DEFINE2(creat, const char __user *, pathname, umode_t, mode)
{
	long fd;

	syscall_filename(pathname);
	syscall_enter("mode: %x\n", mode);

	fd = do_sys_open(AT_FDCWD, pathname, O_CREAT | O_WRONLY | O_TRUNC | O_LARGEFILE, mode);

	syscall_exit(fd);
	return fd;
}

SYSCALL_DEFINE1(close, unsigned int, fd)
{
	struct file *f = NULL;
	struct files_struct *files = current->files;
	int ret;

	spin_lock(&files->file_lock);
	if (likely(test_bit(fd, files->fd_bitmap))) {
		f = files->fd_array[fd];
		BUG_ON(!f);

		if (f->f_op->release)
			f->f_op->release(f);
		put_file(f);
		__clear_bit(fd, files->fd_bitmap);
		files->fd_array[fd] = NULL;

		__clear_close_on_exec(fd, files);
		ret = 0;
	} else {
		ret = -EBADF;
	}
	spin_unlock(&files->file_lock);

	return ret;
}

SYSCALL_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd)
{
	struct file *f = NULL;
	struct files_struct *files = current->files;
	int ret = newfd;

	if (oldfd == newfd)
		return -EINVAL;

	if (newfd >= NR_OPEN_DEFAULT)
		return -EBADF;

	f = fdget(oldfd);
	if (!f)
		return -EBADF;

	spin_lock(&files->file_lock);
	__set_bit(newfd, files->fd_bitmap);
	__clear_close_on_exec(newfd, files);

	/* pervious fdget already incr file ref */
	files->fd_array[newfd] = f;
	spin_unlock(&files->file_lock);

	return ret;
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
