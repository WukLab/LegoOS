/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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
#include <lego/fit_ibapi.h>
#include <processor/fs.h>
#include <processor/processor.h>

static void dummy_fillstat(struct kstat *stat)
{

	stat->dev = 0;
	stat->ino = 0;
	stat->mode = S_IRWXO | S_IRWXG | S_IRWXU;
	stat->nlink = 1;
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

static inline void __pipe_fillstat(struct kstat *stat)
{
	stat->mode |= S_IFIFO;
	stat->blksize = 4096;
}

/*
 * XXX:
 * currently our dev files are all char devices
 * Change when you have some block devices
 */
static inline void __dev_fillstat(struct kstat *stat)
{
	stat->mode |= S_IFCHR;
}

static inline void __sock_fillstat(struct kstat *stat)
{
	stat->mode |= S_IFSOCK;
}

static inline void __proc_fillstat(struct kstat *stat)
{
	WARN(1, "TODO: stat proc file would not happen in general cases.\n");
}

static inline void __sys_fillstat(struct kstat *stat)
{
	WARN(1, "TODO: stat sys file would not happen in general cases.\n");
}

/*
 * Handle stat on special files
 * - pipe
 * - socket
 * - /dev
 * - /proc
 * - /sys
 *
 * Return true if @kname is a special file and we've already
 * filled @stat. Otherwise return false.
 */
static bool special_fillstat(char *kname, struct kstat *stat)
{
	bool is_special;

	BUG_ON(!kname || !stat);
	dummy_fillstat(stat);

	is_special = true;
	if (dev_file(kname))
		__dev_fillstat(stat);
	else if (pipe_file(kname))
		__pipe_fillstat(stat);
	else if (socket_file(kname))
		__sock_fillstat(stat);
	else if (sys_file(kname))
		__sys_fillstat(stat);
	else if (proc_file(kname))
		__proc_fillstat(stat);
	else
		is_special = false;

	return is_special;
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

#ifndef CONFIG_USE_RAMFS
/*
 * get_kstat_from_storage: get corresponding stats specific path
 * @filepath: full pathname on storage side
 * @stat: address of a struct kstat to be filled with
 * @flag: flag passed to storage side for fstatat request
 * return value: 0 on success, -errno on fail
 */

static int get_kstat_from_storage(char *filepath, struct kstat *stat, int flag)
{
	u32 *opcode;
	void *msg, *retbuf;
	int len_ret, len_msg;
	int ret, *retval_in_retbuf;
	struct p2s_stat_struct *payload;
	struct kstat *kstat_in_retbuf;

	len_msg = sizeof(*opcode) + sizeof(*payload);
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	opcode = msg;
	*opcode = P2S_STAT;

	payload = msg + sizeof(*opcode);
	strncpy(payload->filename, filepath, MAX_FILENAME_LENGTH);
	payload->flag = flag;

	len_ret = sizeof(int) + sizeof(struct kstat);
	retbuf = kmalloc(len_ret, GFP_KERNEL);
	if (!retbuf) {
		ret = -ENOMEM;
		goto free_msg;
	}

	ret = ibapi_send_reply_imm(current_storage_home_node(), msg, len_msg,
				   retbuf, len_ret, false);
	if (ret != len_ret) {
		ret = -EIO;
		goto free;
	}

	retval_in_retbuf = retbuf;
	kstat_in_retbuf = retbuf + sizeof(int);

	*stat = *kstat_in_retbuf;
	ret = *retval_in_retbuf;

free:
	kfree(retbuf);
free_msg:
	kfree(msg);
	return ret;
}
#endif

SYSCALL_DEFINE2(newstat, const char __user *, filename,
		struct stat __user *, statbuf)
{
	char kname[FILENAME_LEN_DEFAULT];
	struct kstat stat;
	long ret;

	if (strncpy_from_user(kname, filename, FILENAME_LEN_DEFAULT) < 0) {
		ret = -EFAULT;
		goto out;
	}

	syscall_enter("filename: %s, statbuf: %p\n", kname, statbuf);

	/* Some library workaround */
	if (f_name_equal(kname,
		"/etc/sysconfig/64bit_strstr_via_64bit_strstr_sse2_unaligned")) {
		ret = -ENOENT;
		goto out;
	}

	ret = special_fillstat(kname, &stat);
	if (ret)
		goto fill;

	/*
	 * If it is not a special file, then we need to
	 * ask remote storage for it.
	 */
#ifdef CONFIG_USE_RAMFS
	stat.mode |= S_IFREG;
#else
	ret = get_kstat_from_storage(kname, &stat, 0);
	if (ret)
		goto out;
#endif

fill:
	ret = cp_new_stat(&stat, statbuf);
out:
	syscall_exit(ret);
	return ret;
}

SYSCALL_DEFINE2(newlstat, const char __user *, filename,
		struct stat __user *, statbuf)
{
	char kname[FILENAME_LEN_DEFAULT];
	struct kstat stat;
	long ret;

	if (strncpy_from_user(kname, filename, FILENAME_LEN_DEFAULT) < 0) {
		ret = -EFAULT;
		goto out;
	}

	syscall_enter("filename: %s, statbuf: %p\n", kname, statbuf);

	ret = special_fillstat(kname, &stat);
	if (ret)
		goto fill;

#ifdef CONFIG_USE_RAMFS
	stat.mode |= S_IFREG;
#else
	ret = get_kstat_from_storage(kname, &stat, AT_SYMLINK_NOFOLLOW);
	if (ret) 
		goto out;
#endif

fill:
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

	syscall_enter("fd: %u, statbuf: %p\n", fd, statbuf);

	f = fdget(fd);
	if (!f) {
		ret = -EBADF;
		goto out;
	}
	
	ret = special_fillstat(f->f_name, &stat);
	if (ret)
		goto fill;

#ifndef CONFIG_USE_RAMFS
	ret = get_kstat_from_storage(f->f_name, &stat, 0);
	if (ret)
		goto out;
#endif

fill:
	ret = cp_new_stat(&stat, statbuf);
out:
	syscall_exit(ret);
	return ret;
}

SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
		struct stat __user *, statbuf, int, flag)
{
	char kname[FILENAME_LEN_DEFAULT];
	struct kstat stat;
	long ret;

	ret = get_absolute_pathname(dfd, kname, filename);
	if (ret)
		goto out;

	syscall_enter("filename: %s, statbuf: %p\n", kname, statbuf);

	ret = special_fillstat(kname, &stat);
	if (ret)
		goto fill;

#ifdef CONFIG_USE_RAMFS
	stat.mode |= S_IFREG;
#else
	ret = get_kstat_from_storage(kname, &stat, flag);
	if (ret)
		goto out;
#endif

fill:
	ret = cp_new_stat(&stat, statbuf);
out:
	syscall_exit(ret);
	return ret;
}

/*
 * do_readlinkat: read symbolic link from storage side
 * @dfd: directory file descriptor of relative path resolving root
 * @pathname: pathname of target link name
 * @buf: buffer to put readlink result
 * @bufsiz: user buffer size
 * return value: nrbytes read on success, -errno on fail
 */
static long do_readlinkat(int dfd, const char __user *pathname,
		char __user *buf, int bufsiz)
{
	long ret;
	void *msg;
	u32 *opcode;
	struct p2s_readlink_struct *payload;
	u32 len_msg = sizeof(*opcode) + sizeof(*payload);
	
	/* retval (8 bytes) + content */
	void *retbuf;
	u32 len_retbuf;
	int retlen;
	char *kbuf;

	if (unlikely(bufsiz <= 0))
		return -EINVAL;

	len_retbuf = sizeof(long) + bufsiz;
	retbuf = kmalloc(len_retbuf, GFP_KERNEL);
	if (unlikely(!retbuf)) {
		return -ENOMEM;
	}
	kbuf = retbuf + sizeof(long);
	
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		kfree(retbuf);
		return -ENOMEM;
	}

	opcode = msg;
	payload = msg + sizeof(*opcode);
	*opcode = P2S_READLINK;
	payload->bufsiz = bufsiz;
	ret = get_absolute_pathname(dfd, payload->filename, pathname);
	
	if (unlikely(ret))
		goto free;

	retlen = ibapi_send_reply_imm(current_storage_home_node(), msg, len_msg,
			retbuf, len_retbuf, false);
	/* error in storage side */
	if (unlikely(retlen == sizeof(ret))) {
		ret = *((long *) retbuf);
		goto free;
	}

	if (copy_to_user(buf, kbuf, bufsiz)) {
		ret = -EFAULT;
		goto free;
	}
	ret = *(long *)retbuf;
free:
	kfree(msg);
	kfree(retbuf);
	return ret;
}

SYSCALL_DEFINE3(readlink, const char __user *, path, char __user *, buf,
		int, bufsiz)
{
	long ret;
	syscall_filename(path);
	syscall_enter("bufsiz %d\n", bufsiz);
	ret = do_readlinkat(AT_FDCWD, path, buf, bufsiz);

	syscall_exit(ret);
	return ret;
}
