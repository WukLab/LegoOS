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
#include <processor/fs.h>
#include <processor/processor.h>
#include <lego/comp_common.h>
#include <lego/fit_ibapi.h>

/*
 * Check if a pathname is starts from "/".
 * Return 1 if that is the case.
 */
static inline int absolute_pathname(const char *pathname)
{
	return !memcmp(pathname, "/", 1);
}

/* TODO: implement cwd */
static inline void do_setcwd(const char *pathname)
{
	return;
}

static inline const char *do_getcwd(void)
{
	return "/";
}

/* getcwd: fill user buffer with current working directory
 * @buf: user buffer to be filled
 * @size: max size allowed to be filled
 * return value: len of string - cwd, errno on fail
 */
SYSCALL_DEFINE2(getcwd, char __user *, buf, unsigned long, size)
{
	long error;
	unsigned long len = 2;

	syscall_enter("size %lu\n", size);

	if (size >= len) {
		error = copy_to_user(buf, do_getcwd(), len);
		if (error) {
			error = -EFAULT;
			goto out;
		}
		error = len;
		goto out;
	} else {
		error = -ERANGE;
		goto out;
	}

out:
	syscall_exit(error);
	return error;
}

/*
 * get_absolute_pathname	-	fill a kernel buffer with full pathname
 * @dfd: directory file descriptor of relative path
 * @pathname: source pathname from user space
 * @k_pathname: destination buffer, will be filled with absolute path on success.
 *
 * Return value: 0 on success.
 * Callers: openat, unlinkat, unlink, etc.
 */
int get_absolute_pathname(int dfd, char *k_pathname, const char __user *pathname)
{
	char k_buff[FILENAME_LEN_DEFAULT];
	struct file *f = NULL;

	if (strncpy_from_user(k_buff, pathname, FILENAME_LEN_DEFAULT) < 0)
		return -EFAULT;

	if (dfd == AT_FDCWD)
		goto strcat;

	f = fdget(dfd);
	if (!f)
		return -EBADF;

strcat:
	if (likely(absolute_pathname(pathname)))
		strncpy(k_pathname, k_buff, FILENAME_LEN_DEFAULT);
	else {
		/*
		 * Manually construct an absolute pathname, either
		 *  - combine with cwd
		 *  - or, combine with dfd->f_name
		 */
		if (dfd == AT_FDCWD)
			/*
			 * TODO: replace with current working directory
			 * from open(), creat(), but pathname does not start from "/".
			 */
			strncpy(k_pathname, do_getcwd(), FILENAME_LEN_DEFAULT);
		else {
			/* from openat() */
			strncpy(k_pathname, f->f_name, FILENAME_LEN_DEFAULT);
			if (k_pathname[strlen(k_pathname) - 1] != '/')
				strlcat(k_pathname, "/", FILENAME_LEN_DEFAULT);
		}

		strlcat(k_pathname, k_buff, FILENAME_LEN_DEFAULT);
	}

	if (f)
		put_file(f);
	return 0;
}

static long do_rmdir(int dfd, const char __user *pathname)
{
	long ret;
	void *msg;
	u32 *opcode;
	struct p2s_rmdir_struct *payload;
	u32 len_msg = sizeof(*opcode) + sizeof(*payload);
	int storage_node;

	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		ret = -ENOMEM;
		goto out;
	}

	opcode = msg;
	payload = msg + sizeof(*opcode);
	*opcode = P2S_RMDIR;

	ret = get_absolute_pathname(dfd, payload->filename, pathname);

	if (ret) {
		kfree(msg);
		goto out;
	}

	storage_node = current_storage_home_node();
	ibapi_send_reply_imm(storage_node, msg, len_msg, &ret, sizeof(ret), false);

	kfree(msg);

out:
	return ret;
}

SYSCALL_DEFINE1(rmdir, const char __user *, pathname)
{
	long ret;

	syscall_filename(pathname);
	ret = do_rmdir(AT_FDCWD, pathname);
	syscall_exit(ret);

	return ret;
}

static long do_unlinkat(int dfd, const char __user *pathname)
{
	long ret;
	void *msg;
	u32 *opcode;
	struct p2s_unlink_struct *payload;
	u32 len_msg = sizeof(*opcode) + sizeof(*payload);
	int storage_node;

	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		ret = -ENOMEM;
		goto out;
	}

	opcode = msg;
	payload = msg + sizeof(*opcode);
	*opcode = P2S_UNLINK;

	ret = get_absolute_pathname(dfd, payload->filename, pathname);

	if (ret) {
		kfree(msg);
		goto out;
	}

	storage_node = current_storage_home_node();
	ibapi_send_reply_imm(storage_node, msg, len_msg, &ret, sizeof(ret), false);

	kfree(msg);

out:
	return ret;
}

SYSCALL_DEFINE1(unlink, const char __user *, pathname)
{
	long ret;

	syscall_filename(pathname);
	ret = do_unlinkat(AT_FDCWD, pathname);
	syscall_exit(ret);

	return ret;
}

SYSCALL_DEFINE3(unlinkat, int, dfd, const char __user *, pathname, int, flag)
{
	long ret;

	syscall_filename(pathname);
	syscall_enter("dfd: %d, flag: %d\n", dfd, flag);

	if ((flag & ~AT_REMOVEDIR) != 0) {
		ret = -EINVAL;
		goto out;
	}

	if (flag & AT_REMOVEDIR) {
		ret = do_rmdir(dfd, pathname);
		goto out;
	}

	ret = do_unlinkat(dfd, pathname);

out:
	syscall_exit(ret);
	return ret;
}

SYSCALL_DEFINE2(mkdir, const char __user *, pathname, umode_t, mode)
{
	long ret;
	void *msg;
	u32 *opcode;
	struct p2s_mkdir_struct *payload;
	u32 len_msg = sizeof(*opcode) + sizeof(*payload);
	int storage_node;

	syscall_filename(pathname);
	syscall_enter("mode: %u", mode);

	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		ret = -ENOMEM;
		goto out;
	}

	opcode = msg;
	payload = msg + sizeof(*opcode);
	*opcode = P2S_MKDIR;

	if (strncpy_from_user(payload->filename, pathname, FILENAME_LEN_DEFAULT) < 0) {
		ret = -EFAULT;
		kfree(msg);
		goto out;
	}

	payload->mode = mode;

	storage_node = current_storage_home_node();
	ibapi_send_reply_imm(storage_node, msg, len_msg, &ret, sizeof(ret), false);
	kfree(msg);

out:
	syscall_exit(ret);
	return ret;
}

/* getdents */
struct lego_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

SYSCALL_DEFINE3(getdents, unsigned int, fd,
		struct lego_dirent __user *, dirent, unsigned int, count)
{
	long ret;
	void *msg;
	u32 *opcode;
	struct p2s_getdents_struct *payload;
	u32 len_msg = sizeof(*opcode) + sizeof(*payload);
	struct file *f;

	void *retbuf;
	struct p2s_getdents_retval_struct *retval_struct;
	u32 len_retbuf = sizeof(*retval_struct) + count;
	struct lego_dirent *k_dirent;
	int retlen;

	syscall_enter("fd: %d, count: %u\n", fd, count);

	f = fdget(fd);
	if (!f) {
		ret = -EBADF;
		goto out;
	}

	retbuf = kmalloc(len_retbuf, GFP_KERNEL);
	if (unlikely(!retbuf)) {
		ret = -ENOMEM;
		goto out;
	}

	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		kfree(retbuf);
		ret = -ENOMEM;
		goto out;
	}

	opcode = msg;
	payload = msg + sizeof(*opcode);
	*opcode = P2S_GETDENTS;
	strncpy(payload->filename, f->f_name, MAX_FILENAME_LENGTH);
	payload->pos = f->f_pos;
	payload->count = count;

	retlen = ibapi_send_reply_imm(current_storage_home_node(), msg, len_msg,
			retbuf, len_retbuf, false);
	/* error in storage side */
	if (unlikely(retlen == sizeof(ret))) {
		ret = *((long *) retbuf);
		goto free;
	}

	retval_struct = retbuf;
	k_dirent = retbuf + sizeof(*retval_struct);
	ret = retval_struct->retval;
	f->f_pos = retval_struct->pos;
	put_file(f);

	if (copy_to_user(dirent, k_dirent, count)) {
		ret = -EFAULT;
		goto free;
	}

free:
	kfree(msg);
	kfree(retbuf);
out:
	syscall_exit(ret);
	return ret;
}

#ifndef CONFIG_MEM_PAGE_CACHE
/*
 * do_rename: send rename request side directly
 * if NO CONFIG_MEM_PAGE_CACHE, P->S directly
 */
static long do_rename(const char __user *oldname, const char __user *newname)
{
	long ret;
	void *msg;
	u32 *opcode;
	struct p2s_rename_struct *payload;
	u32 len_msg = sizeof(*opcode) + sizeof(*payload);

	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		ret = -ENOMEM;
		goto out;
	}

	opcode = msg;
	payload = msg + sizeof(*opcode);
	*opcode = P2S_RENAME;

	ret = get_absolute_pathname(AT_FDCWD, payload->oldname, oldname);
	if (ret) {
		kfree(msg);
		goto out;
	}

	ret = get_absolute_pathname(AT_FDCWD, payload->newname, newname);
	if (ret) {
		kfree(msg);
		goto out;
	}

	ibapi_send_reply_imm(current_storage_home_node(), msg, len_msg,
				&ret, sizeof(ret), false);

	kfree(msg);

out:
	return ret;
}
#else
/*
 * do_rename: send rename request side directly
 * if we are using page cache from memory component
 * we cannot send rename request directly to storage
 */
static long do_rename(const char __user *oldname, const char __user *newname)
{
	long ret;
	void *msg;
	struct common_header *hdr;
	struct p2m_rename_struct *payload;
	u32 len_msg = sizeof(*hdr) + sizeof(*payload);

	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		ret = -ENOMEM;
		goto out;
	}

	hdr = msg;
	hdr->opcode = P2S_RENAME;
	hdr->src_nid = LEGO_LOCAL_NID;
	hdr->length = len_msg;

	payload = msg + sizeof(*hdr);
	payload->storage_node = current_storage_home_node();

	ret = get_absolute_pathname(AT_FDCWD, payload->oldname, oldname);
	if (ret) {
		kfree(msg);
		goto out;
	}

	ret = get_absolute_pathname(AT_FDCWD, payload->newname, newname);
	if (ret) {
		kfree(msg);
		goto out;
	}

	ibapi_send_reply_imm(current_pgcache_home_node(), msg, len_msg,
				&ret, sizeof(ret), false);

	kfree(msg);

out:
	return ret;
}
#endif /* CONFIG_MEM_PAGE_CACHE */

SYSCALL_DEFINE2(rename, const char __user *, oldname,
		const char __user *, newname)
{
	return do_rename(oldname, newname);
}

/*
 * XXX:
 * The current implementation of fsync is not complete.
 * Currently we only send fsync() to M if page cache is enabled.
 * In fact, we should handle all the following cases:
 * 1) If pgcache is not enabled, send request to Storage
 * 2) Flush back dirty pcache lines
 */
SYSCALL_DEFINE1(fsync, unsigned int, fd)
{
#ifdef CONFIG_MEM_PAGE_CACHE
	long ret;
	void *msg;
	struct common_header *hdr;
	struct file *f;
	struct p2m_fsync_struct *payload;
	u32 len_msg = sizeof(*hdr) + sizeof(*payload);

	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		ret = -ENOMEM;
		goto out;
	}

	f = fdget(fd);
	if (unlikely(!f)) {
		kfree(msg);
		return -EBADF;
	}

	hdr = msg;
	hdr->opcode = P2M_FSYNC;
	hdr->src_nid = LEGO_LOCAL_NID;
	hdr->length = len_msg;

	payload = msg + sizeof(*hdr);
	payload->storage_node = current_storage_home_node();
	strncpy(payload->filename, f->f_name, MAX_FILENAME_LENGTH);

	ibapi_send_reply_imm(current_pgcache_home_node(), msg, len_msg,
				&ret, sizeof(ret), false);

	kfree(msg);

out:
	put_file(f);
	return ret;
#else
	return 0;
#endif /* CONFIG_MEM_PAGE_CACHE */
}
