/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/time.h>
#include <lego/stat.h>
#include <lego/slab.h>
#include <lego/uaccess.h>
#include <lego/files.h>
#include <lego/syscalls.h>
#include <lego/comp_processor.h>

#include "internal.h"

static void dummy_fillstat(struct kstat *stat)
{

	stat->dev = 0;
	stat->ino = 0;
	stat->mode = S_IRWXO | S_IRWXG | S_IRWXU;
	stat->nlink = 0;
	stat->uid = current_uid();
	stat->gid = current_gid();
	stat->rdev = 0;
	stat->size = 0;
	stat->atime = CURRENT_TIME;
	stat->mtime = CURRENT_TIME;
	stat->ctime = CURRENT_TIME;
	stat->blksize = 1024;
	stat->blocks = 0;
}

static int cp_new_stat(struct kstat *stat, struct stat __user *statbuf)
{
	struct stat tmp;

	INIT_STRUCT_STAT_PADDING(tmp);
	tmp.st_dev = stat->dev;
	tmp.st_ino = stat->ino;
	if (sizeof(tmp.st_ino) < sizeof(stat->ino) && tmp.st_ino != stat->ino)
		return -EOVERFLOW;
	tmp.st_mode = stat->mode;
	tmp.st_nlink = stat->nlink;
	if (tmp.st_nlink != stat->nlink)
		return -EOVERFLOW;
	tmp.st_uid = stat->uid;
	tmp.st_gid = stat->gid;
	tmp.st_rdev = stat->rdev;
	tmp.st_size = stat->size;
	tmp.st_atime = stat->atime.tv_sec;
	tmp.st_mtime = stat->mtime.tv_sec;
	tmp.st_ctime = stat->ctime.tv_sec;
	tmp.st_atime_nsec = stat->atime.tv_nsec;
	tmp.st_mtime_nsec = stat->mtime.tv_nsec;
	tmp.st_ctime_nsec = stat->ctime.tv_nsec;
	tmp.st_blocks = stat->blocks;
	tmp.st_blksize = stat->blksize;
	return copy_to_user(statbuf, &tmp, sizeof(tmp)) ? -EFAULT : 0;
}

static int handle_special_stat(char *f_name)
{
	if (f_name_equal(f_name,
		"/etc/sysconfig/64bit_strstr_via_64bit_strstr_sse2_unaligned"))
		return -ENOENT;
	else
		return 0;
}

SYSCALL_DEFINE2(newstat, const char __user *, filename,
		struct stat __user *, statbuf)
{
	char buf[FILENAME_LEN_DEFAULT];
	struct kstat stat;
	long ret;

	syscall_enter();

	ret = strncpy_from_user(buf, filename, FILENAME_LEN_DEFAULT);
	if (ret < 0)
		goto out;
	pr_info("%s(): filename: %s\n", __func__, buf);

	ret = handle_special_stat(buf);
	if (ret)
		goto out;

	dummy_fillstat(&stat);
	stat.mode |= S_IFREG;
	ret = cp_new_stat(&stat, statbuf);

out:
	syscall_exit(ret);
	return ret;
}

SYSCALL_DEFINE2(newlstat, const char __user *, filename,
		struct stat __user *, statbuf)
{
	char buf[FILENAME_LEN_DEFAULT];
	struct kstat stat;
	long ret;

	syscall_enter();

	ret = strncpy_from_user(buf, filename, FILENAME_LEN_DEFAULT);
	if (ret < 0)
		goto out;
	pr_info("%s(): filename: %s\n", __func__, buf);

	dummy_fillstat(&stat);
	stat.mode |= S_IFREG;
	ret = cp_new_stat(&stat, statbuf);

out:
	syscall_exit(ret);
	return ret;
}

SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)
{
	struct file *f;
	struct kstat stat;
	int ret;

	syscall_enter();
	pr_info("%s(): fd: %u, statbuf: %p\n",
		__func__, fd, statbuf);

	f = fdget(fd);
	if (unlikely(!f)) {
		ret = -EBADF;
		goto out;
	}

	dummy_fillstat(&stat);
	if (fd <= 2)
		/* STDIN, STDOUT, STDERR */
		stat.mode |= S_IFBLK;
	else
		stat.mode |= S_IFREG;
	ret = cp_new_stat(&stat, statbuf);

out:
	syscall_exit(ret);
	return ret;
}
