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
 * get_file_size: get up-to-date file size from page cache(memory component)
 * callers: lseek
 * @pathname: full path of the file.
 % @to_storage: if false, will return -ENOENT if file is not in page cache
 * retval: sizeof the file.
 */
ssize_t get_file_size(const char *pathname)
{
	ssize_t ret = 0;
	void *msg;
	struct common_header *hdr;
	int pgcache_node;
	struct p2m_lseek_struct *payload;
	u32 len_msg = sizeof(*hdr) + sizeof(*payload);
	
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		ret = -ENOMEM;
		goto out;
	}

	hdr = msg;
	hdr->opcode = P2M_LSEEK;
	hdr->src_nid = LEGO_LOCAL_NID;
	hdr->length = len_msg;

	payload = msg + sizeof(*hdr);
	strncpy(payload->filename, pathname, FILENAME_LEN_DEFAULT);

	pgcache_node = current_pgcache_home_node();
	payload->storage_node = current_storage_home_node();

	ibapi_send_reply_imm(pgcache_node, msg, len_msg, &ret, sizeof(ret), false);

	kfree(msg);
out:
	return ret;
}
