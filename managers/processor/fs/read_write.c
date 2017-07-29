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
#include <lego/comp_processor.h>

SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	debug_syscall_print();
	pr_info("%s(): fd: %d, buf: %p, count: %zu\n",
		__func__, fd, buf, count);
	return -EFAULT;
}

SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	char *s;

	debug_syscall_print();

	s = kmalloc(count, GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	if (copy_from_user(s, buf, count))
		return -EFAULT;

	pr_info("%s(): buf: %s\n", __func__, s);

	return count;
}

SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
	char name[FILENAME_LEN_DEFAULT];

	debug_syscall_print();

	if (strncpy_from_user(name, filename, FILENAME_LEN_DEFAULT) < 0)
		return -EFAULT;

	pr_info("%s(): %p [%s]\n",
		__func__, filename, name);
	return 66;
}

SYSCALL_DEFINE1(close, unsigned int, fd)
{
	debug_syscall_print();
	pr_info("%s(): fd: %d\n", __func__, fd);
	return -EFAULT;
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

	kvec = kmalloc(vlen * sizeof(*kvec), GFP_KERNEL);
	if (!kvec)
		return -ENOMEM;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
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
	}

free:
	kfree(kvec);
	kfree(buf);
	return ret;
}

SYSCALL_DEFINE3(readv, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	debug_syscall_print();
	return do_readv(fd, vec, vlen, 0);
}

SYSCALL_DEFINE3(writev, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
	debug_syscall_print();
	return do_writev(fd, vec, vlen, 0);
}
