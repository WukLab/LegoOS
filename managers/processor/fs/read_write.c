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
#include <processor/fs.h>
#include <processor/processor.h>

SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	struct file *f;
	long ret;
	loff_t pos;

	syscall_enter("fd: %d, buf: %p, count: %zu\n",
		fd, buf, count);

	f = fdget(fd);
	if (!f) {
		ret = -EBADF;
		goto out;
	}

	/*
	 * f_pos is updated without locking
	 * synchronization is maintained by application
	 */
	pos = f->f_pos;
	ret = f->f_op->read(f, buf, count, &pos);
	f->f_pos = pos;

	put_file(f);
out:
	syscall_exit(ret);
	return ret;
}

SYSCALL_DEFINE4(pread64, unsigned int, fd, char __user *, buf,
		size_t, count, loff_t, pos)
{
	struct file *f;
	long ret;

	syscall_enter("fd: %d, buf: %p, count: %zu, pos: %Ld\n",
		fd, buf, count, pos);

	if (pos < 0) {
		ret = -EINVAL;
		goto out;
	}

	f = fdget(fd);
	if (!f) {
		ret = -EBADF;
		goto out;
	}

	ret = f->f_op->read(f, buf, count, &pos);

	put_file(f);
out:
	syscall_exit(ret);
	return ret;
}

SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	struct file *f;
	long ret;
	loff_t pos;

	syscall_enter("fd: %d buf: %p count: %zu\n",
		fd, buf, count);

	f = fdget(fd);
	if (!f) {
		ret = -EBADF;
		goto out;
	}

	/*
	 * f_pos is updated without locking
	 * synchronization is maintained by application
	 */
	pos = f->f_pos;
	ret = f->f_op->write(f, buf, count, &pos);
	f->f_pos = pos;

	put_file(f);
out:
	syscall_exit(ret);
	return ret;
}

SYSCALL_DEFINE4(pwrite64, unsigned int, fd, const char __user *, buf,
		size_t, count, loff_t, pos)
{
	struct file *f;
	long ret;

	syscall_enter("fd: %d buf: %p count: %zu, pos: %Ld\n",
		fd, buf, count, pos);

	if (pos < 0) {
		ret = -EINVAL;
		goto out;
	}

	f = fdget(fd);
	if (!f) {
		ret = -EBADF;
		goto out;
	}
	
	ret = f->f_op->write(f, buf, count, &pos);

	put_file(f);
out:
	syscall_exit(ret);
	return ret;
}

/* fake sync() */
SYSCALL_DEFINE0(sync)
{
	return 0;
}

static ssize_t do_readv(unsigned long fd, const struct iovec __user *vec,
			unsigned long vlen, int flags)
{
	pr_info("%s: fd: %lu\n", __func__, fd);
	return -EFAULT;
}

static ssize_t do_writev(unsigned long fd, const struct iovec __user *vec,
			 unsigned long vlen, int flags)
{
	struct iovec *kvec;
	char *buf;
	int i;
	ssize_t ret = 0;

	pr_info("%s: fd: %lu, nrvec: %lu\n",
		__func__, fd, vlen);

	kvec = kzalloc(vlen * sizeof(*kvec), GFP_KERNEL);
	if (!kvec)
		return -ENOMEM;

	buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		kfree(kvec);
		return -ENOMEM;
	}

	if (copy_from_user(kvec, vec, vlen * sizeof(*kvec))) {
		ret = -EFAULT;
		goto free;
	}

	for (i = 0; i < vlen; i++) {
		if (copy_from_user(buf, kvec[i].iov_base, kvec[i].iov_len)) {
			ret = -EFAULT;
			goto free;
		}
		ret += kvec[i].iov_len;

		pr_info("  vec[%d]: %s\n", i, buf);
		memset(buf, 0, PAGE_SIZE);
	}

free:
	kfree(kvec);
	kfree(buf);
	return ret;
}

SYSCALL_DEFINE3(readv, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	long ret;

	syscall_enter("fd: %lu, vec: %p, vlen: %#lx\n",
		fd, vec, vlen);
	ret = do_readv(fd, vec, vlen, 0);
	syscall_exit(ret);
	return ret;
}

SYSCALL_DEFINE3(writev, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	long ret;

	syscall_enter("fd: %lu, vec: %p, vlen: %#lx\n",
		fd, vec, vlen);
	ret = do_writev(fd, vec, vlen, 0);
	syscall_exit(ret);
	return ret;
}
