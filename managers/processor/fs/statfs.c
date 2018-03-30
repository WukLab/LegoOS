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
 * do_p2s_kstatfs: get kstatfs struct from storage side
 * @kpathname: full pathname of a file on storage component
 * @kbuf: pointer to kstatfs to be filled with, should be perallocated
 * by caller
 * return value: 0 on success, -errno on fail
 */
static long do_p2s_kstatfs(const char *kpathname, struct lego_kstatfs *kbuf)
{
	long ret;
	void *msg;
	u32 *opcode;
	struct p2s_statfs_struct *payload;
	u32 storage_node_id, len_msg = sizeof(*opcode) + sizeof(*payload);

	struct p2s_statfs_ret_struct retbuf;
	int retlen;
	
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		ret = -ENOMEM;
		goto out;
	}
	
	opcode = msg;
	payload = msg + sizeof(*opcode);
	*opcode = P2S_STATFS;
	strncpy(payload->filename, kpathname, FILENAME_LEN_DEFAULT);

	storage_node_id = current_storage_home_node();

	retlen = ibapi_send_reply_imm(storage_node_id, msg, len_msg, &retbuf,
			sizeof(retbuf), false);
	
	if (unlikely(retlen != sizeof(retbuf))) {
		ret = -EIO;
		goto free;
	}

	memcpy(kbuf, &retbuf.kstatfs, sizeof(*kbuf));
	ret = retbuf.retval;

free:
	kfree(msg);
out:
	return ret;
}

SYSCALL_DEFINE2(statfs, const char __user *, pathname, struct statfs __user *, buf)
{
	long ret;
	char k_name_buf[FILENAME_LEN_DEFAULT];
	struct lego_kstatfs k_statfs_buf;

	ret = get_absolute_pathname(AT_FDCWD, k_name_buf, pathname);
	if (ret)
		goto out;
	
	syscall_enter("pathname: %s, buf addr %p\n", k_name_buf, buf);

	/* 
	 * TODO: replace correct special files
	 * set -ENOENT for simplicity
	 */
	if (sys_file(k_name_buf) || proc_file(k_name_buf)
		|| dev_file(k_name_buf))
		return -ENOENT;

	ret = do_p2s_kstatfs(k_name_buf, &k_statfs_buf);

	/* exactly same length */
	if (copy_to_user(buf, &k_statfs_buf, sizeof(k_statfs_buf)))
		ret = -EFAULT;

out:
	syscall_exit(ret);
	return ret;
}
