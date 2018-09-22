/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/files.h>
#include <lego/hashtable.h>
#include <lego/fit_ibapi.h>
#include <memory/pgcache.h>

static long do_m2s_rename(char *oldname, char *newname, __u32 storage_node)
{
	long ret;
	void *msg;
	u32 *opcode;
	/* reuse p2s_rename_struct */
	struct p2s_rename_struct *payload;
	int retlen;
	u32 len_msg = sizeof(*opcode) + sizeof(*payload);

	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		ret = -ENOMEM;
		goto out;
	}

	opcode = msg;
	payload = msg + sizeof(*opcode);
	*opcode = P2S_RENAME;

	strncpy(payload->oldname, oldname, FILENAME_LEN_DEFAULT);
	strncpy(payload->newname, newname, FILENAME_LEN_DEFAULT);


	retlen = ibapi_send_reply_imm(storage_node, msg, len_msg,
				&ret, sizeof(ret), false);
	if (unlikely(retlen != sizeof(ret)))
		ret = -EIO;

	kfree(msg);
out:
	return ret;
}

static void __do_page_cache_rename(char *oldname, char *newname)
{
	size_t len = 0;
	loff_t curr = 0;
	struct lego_pgcache_file *pgfile = find_lego_pgcache_file(oldname);
	loff_t stride = 1 << PGCACHE_PREFETCH_ORDER;

	/* file has not been touched yet */
	if (unlikely(!pgfile))
		return;

	len = file_size_read(pgfile);
	while (curr < len) {
		struct lego_pgcache_struct *pgc =
				find_lego_pgcache_struct(oldname, curr);

		if (pgc) {
			ht_remove_lego_pgcache_struct(pgc);
			memset(pgc->filepath, 0, MAX_FILENAME_LENGTH);
			strncpy(pgc->filepath, newname, MAX_FILENAME_LENGTH);
			ht_insert_lego_pgcache_struct(pgc);
		}
		curr += stride;
	}

	/*
	 * rename pgfile
	 */
	ht_remove_lego_pgcache_file(pgfile);
	memset(pgfile->filepath, 0, MAX_FILENAME_LENGTH);
	strncpy(pgfile->filepath, newname, MAX_FILENAME_LENGTH);
	ht_insert_lego_pgcache_file(pgfile);
}

int handle_p2m_rename(struct p2m_rename_struct *payload, struct common_header *hdr,
		      struct thpool_buffer *tb)
{
	long *retval;

	retval = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*retval));
	*retval = do_m2s_rename(payload->oldname,
			payload->newname, payload->storage_node);
	/*
	 * rename failed at storage side
	 */
	if (*retval)
		goto out;

	__do_page_cache_rename(payload->oldname, payload->newname);
out:
	return *retval;
}

/*
 * getting file size
 */
ssize_t get_file_size_from_storage(char *filepath, unsigned int storage_node)
{
	ssize_t ret = 0;
	void *msg;
	u32 *opcode;

	/* reuse p2m_lseek_struct */
	struct m2s_lseek_struct *payload;
	u32 len_msg = sizeof(*opcode) + sizeof(*payload);

	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg))
		return -ENOMEM;

	opcode = msg;
	payload = msg + sizeof(*opcode);
	*opcode = M2S_LSEEK;
	strncpy(payload->filename, filepath, FILENAME_LEN_DEFAULT);

	ibapi_send_reply_imm(storage_node, msg, len_msg, &ret, sizeof(ret), false);
	kfree(msg);

	return ret;
}

int handle_p2m_lseek(struct p2m_lseek_struct *payload, struct common_header *hdr,
		     struct thpool_buffer *tb)
{
	ssize_t *retval;
	struct lego_pgcache_file *file;

	retval = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*retval));
	file = find_lego_pgcache_file(payload->filename);

	/*
	 * file has never been read/write before
	 * directly invoking storage component to get file size
	 */
	if (unlikely(!file)) {
		*retval = get_file_size_from_storage(payload->filename,
						    payload->storage_node);
		goto out;
	}

	*retval = file_size_read(file);

out:
	return *retval;
}

/*
 * get_kstat_from_storage: get corresponding stats specific path
 * @filepath: full pathname on storage side
 * @stat: address of a struct kstat to be filled with
 * @flag: flag passed to storage side for fstatat request
 * return value: 0 on success, -errno on fail
 */

static int do_m2s_stat(char *filepath, struct p2s_stat_ret_struct *retbuf,
			int flag, __u32 storage_node)
{
	u32 *opcode;
	void *msg;
	int len_msg, ret;
	struct p2s_stat_struct *payload;

	len_msg = sizeof(*opcode) + sizeof(*payload);
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	opcode = msg;
	*opcode = P2S_STAT;		/* reuse P2S_STAT */

	payload = msg + sizeof(*opcode);
	strncpy(payload->filename, filepath, MAX_FILENAME_LENGTH);
	payload->flag = flag;

	ret = ibapi_send_reply_imm(storage_node, msg, len_msg,
				   retbuf, sizeof(*retbuf), false);

	if (unlikely(ret != sizeof(*retbuf))) {
		ret = -EIO;
		goto free;
	}

	ret = retbuf->retval;
free:
	kfree(msg);
	return ret;
}

int handle_p2m_stat(struct p2m_stat_struct *payload, struct common_header *hdr,
		    struct thpool_buffer *tb)
{
	int ret;
	struct p2s_stat_ret_struct *retbuf;
	struct lego_pgcache_file *pgcfile;

	retbuf = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*retbuf));
	ret = do_m2s_stat(payload->filename, retbuf,
			  payload->flag, payload->storage_node);

	if (ret < 0)
		goto out;

	pgcfile = find_lego_pgcache_file(payload->filename);
	if (pgcfile) {
		size_t update = file_size_read(pgcfile);
		retbuf->statbuf.size = update;
	}

out:
	return ret;
}
