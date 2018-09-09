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
 * do_truncate: truncate file size to given length
 * @kname: absolute file pathname on storage side
 * @length: size to be truncate to.
 * return value: 0 on success, -errno on fail
 * LIMITATION: only affect storage side file size,
 * file path can only be full pathname
 */
long do_truncate(const char *kname, long length)
{
	long ret;
	void *msg;
	u32 *opcode;
	struct p2s_truncate_struct *payload;
	int len_msg = sizeof(*opcode) + sizeof(*payload);
	int storage_node;

	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg))
		return -EFAULT;

	opcode = msg;
	payload = msg + sizeof(*opcode);
	*opcode = P2S_TRUNCATE;
	strncpy(payload->filename, kname, MAX_FILENAME_LENGTH);
	payload->length = length;

	storage_node = current_storage_home_node();
	ibapi_send_reply_imm(current_storage_home_node(), msg, len_msg,		\
			&ret, sizeof(ret), false);
	
	kfree(msg);
	return ret;
}

SYSCALL_DEFINE2(truncate, const char __user *, path, long, length)
{
	long ret;
	char kname[FILENAME_LEN_DEFAULT];

	if (strncpy_from_user(kname, path, FILENAME_LEN_DEFAULT) < 0) {
		ret =  -EFAULT;
		goto out;
	}

	syscall_enter("path: %s, length: %ld\n", path, length);

	if (proc_file(kname) || sys_file(kname) || dev_file(kname)) {
		ret = -EFAULT;
		goto out;
	}
	ret = do_truncate(kname, length);
out:
	syscall_exit(ret);
	return ret;
}

SYSCALL_DEFINE2(ftruncate, unsigned int, fd, unsigned long, length)
{
	long ret;
	struct file *f;

	syscall_enter("fd: %u, length: %lu\n", fd, length);

	f = fdget(fd);
	if (!f) {
		ret = -EBADF;
		goto out;
	}
	
	if (proc_file(f->f_name) || sys_file(f->f_name) || dev_file(f->f_name)) {
		ret = -EBADF;
		put_file(f);
		goto out;
	}

	ret = do_truncate(f->f_name, length);
out:
	syscall_exit(ret);
	return ret;
}
