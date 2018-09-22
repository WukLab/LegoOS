/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/kernel.h>
#include <lego/slab.h>
#include <lego/hashtable.h>
#include <lego/mm.h>
#include <lego/fit_ibapi.h>
#include <lego/comp_common.h>
#include <lego/comp_memory.h>
#include <lego/comp_storage.h>
#include <memory/vm.h>
#include <memory/file_ops.h>

#include <memory/pgcache.h>

ssize_t pgcache_load(char *f_name, struct lego_pgcache_struct *pgc)
{
	u32 len_msg, len_ret, *opcode;
	void *msg, *retbuf, *content;
	ssize_t retval, *retval_ptr;
	struct m2s_read_write_payload *payload;
	u32 count = 0;

	len_msg = sizeof(*opcode) + sizeof(*payload);
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	/* retbuf = retval + content */
	count = CL_SIZE;
	len_ret = sizeof(retval) + count;
	retbuf = kmalloc(len_ret, GFP_KERNEL);
	if(!retbuf) {
		kfree(msg);
		return -ENOMEM;
	}

	pgcache_debug("pages:%p, offset:%Lx, count:%u, f_name: %s",					\
				pgc->cached_pages, pgc->pos, count, f_name);

	opcode = msg;
	*opcode = M2S_READ;

	payload = msg + sizeof(*opcode);
	payload->uid = 0;		/* legacy, unused */
	payload->flags = O_RDONLY;
	payload->len = count;
	payload->offset = pgc->pos;
	strcpy(payload->filename, f_name);

	ibapi_send_reply_imm(pgc->storage_node, msg, len_msg, retbuf, len_ret, false);
	/* The first 8 bytes are the nr of bytes been read */
	retval_ptr = retbuf;
	retval = *retval_ptr;

	BUG_ON(retval > count);

	/* The left is the content itself */
	content = retbuf + sizeof(*retval_ptr);

	spin_lock(&pgc->lock);
	memcpy(pgc->cached_pages, content, retval);
	pgc->real_len = retval;
	spin_unlock(&pgc->lock);

	kfree(msg);
	kfree(retbuf);

	return retval;
}

ssize_t flush_one_cacheline_locked(struct lego_pgcache_struct *pgc)
{
	u32 len_msg, *opcode;
	void *msg, *content;
	ssize_t retval;
	struct m2s_read_write_payload *payload;

	len_msg = sizeof(*opcode) + sizeof(*payload) + pgc->real_len;
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	opcode = msg;
	*opcode = M2S_WRITE;

	payload = msg + sizeof(*opcode);
	payload->uid = 0;
	payload->flags = O_WRONLY;
	payload->len = pgc->real_len;
	payload->offset = pgc->pos;
	strcpy(payload->filename, pgc->filepath);

	content = msg + sizeof(*opcode) + sizeof(*payload);

	/* COPY content of page cache to payload */
	memcpy(content, pgc->cached_pages, payload->len);

	ibapi_send_reply_imm(pgc->storage_node, msg, len_msg, &retval, sizeof(retval), false);

	kfree(msg);
	return retval;
}

static unsigned int __nr_cachelines(loff_t pos, size_t count)
{
	unsigned int nr_cachelines, cl_size;
	loff_t start, end;
	loff_t _aligned_start, _aligned_end;

	start = pos;
	end = pos + count - 1;
	_aligned_start = aligned_pos(start);
	_aligned_end = aligned_pos(end);
	cl_size = CL_SIZE;

	nr_cachelines = (_aligned_end - _aligned_start)/cl_size + 1;

	pgcache_debug("nr_cachelines:%u", nr_cachelines);

	return nr_cachelines;
}

/* prepare one cacheline
 * return pgc
 */
static struct lego_pgcache_struct *
prepare_cacheline(struct lego_pgcache_file *file, loff_t pos, ssize_t *retval)
{
	struct lego_pgcache_struct *pgc;
	char *f_name = file->filepath;

	pgc = find_lego_pgcache_struct(f_name, pos);
	if (!pgc) {
		pgc = __alloc_pgcache(f_name, pos, file->storage_node);
		if (unlikely(!pgc))
			return NULL;

		pgcache_debug("alloc cachedline: %p", pgc->cached_pages);

		*retval = pgcache_load(f_name, pgc);
		ht_insert_lego_pgcache_struct(pgc);
		return pgc;
	}

	/* no-residental HIR pages */
	if (!pgc->cached_pages) {
		pgc->cached_pages = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,	\
			PGCACHE_PREFETCH_ORDER);
		*retval = pgcache_load(f_name, pgc);
	}

	pgcache_debug("f_name: %s, cacheline:%p", f_name, pgc->cached_pages);

	return pgc;
}

/*
 * paper one cacheline without loading
 * allow to do so if pos is cacheline aligned, and size = cacheline_size
 */
static struct lego_pgcache_struct *
prepare_cacheline_fast(struct lego_pgcache_file *file, loff_t pos, ssize_t *retval)
{
	struct lego_pgcache_struct *pgc;
	char *f_name = file->filepath;

	printk_once("%s()\n", __func__);
	pgc = find_lego_pgcache_struct(f_name, pos);
	if (!pgc) {
		pgc = __alloc_pgcache(f_name, pos, file->storage_node);
		if (unlikely(!pgc))
			return NULL;

		pgcache_debug("alloc cachedline fast: %p", pgc->cached_pages);

		*retval = CL_SIZE;
		ht_insert_lego_pgcache_struct(pgc);
		return pgc;
	}

	/* no-residental HIR pages */
	if (!pgc->cached_pages) {
		pgc->cached_pages = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,	\
			PGCACHE_PREFETCH_ORDER);
		*retval = CL_SIZE;
	}

	pgcache_debug("f_name: %s, cacheline:%p", f_name, pgc->cached_pages);

	return pgc;
}

/* prepare for 2 cachelines, that write/read across cacheline boundaries */
static int prepare_two_cachelines(struct lego_pgcache_file *file, loff_t pos, ssize_t *retval,
		struct lego_pgcache_struct **pgc1, struct lego_pgcache_struct **pgc2)
{
	char *f_name = file->filepath;

	*pgc1 = find_lego_pgcache_struct(f_name, pos);
	if (!(*pgc1)) {
		*pgc1 = __alloc_pgcache(f_name, pos, file->storage_node);
		if (unlikely(!(*pgc1)))
			return -ENOMEM;

		*retval = pgcache_load(f_name, *pgc1);
		ht_insert_lego_pgcache_struct(*pgc1);
	}

	*pgc2 = find_lego_pgcache_struct(f_name, pos);
	if (!(*pgc2)) {
		*pgc2 = __alloc_pgcache(f_name, pos, file->storage_node);
		if (unlikely(!(*pgc2)))
			return -ENOMEM;

		*retval = pgcache_load(f_name, *pgc2);
		ht_insert_lego_pgcache_struct(*pgc2);
	}

	return 0;
}

ssize_t __read_from_one_cacheline(struct lego_task_struct *tsk,
	struct lego_pgcache_file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct lego_pgcache_struct *pgc;
	loff_t ckoff;
	ssize_t retval;
	size_t len = count;
	char *f_name = file->filepath;

	pgc = prepare_cacheline(file, *pos, &retval);
	ckoff = chunk_offset(*pos);

	/* read count cannot be satified */
	if (unlikely(ckoff + count > pgc->real_len))
		len = pgc->real_len - ckoff;

	/* NOMEM for caching */
	if (unlikely(!pgc))
		return __storage_read(tsk, f_name, buf, count, pos);


	pgcache_debug("pgcache vaddr: %p, content: [%s]", pgc->cached_pages + ckoff,
			(char *) pgc->cached_pages + ckoff);


	/*
	 * comment: currently reader does not grab lock, since in memory component
	 * all read/write are handled by one thread, and actually there is no race condition
	 * on concurrent read/write, if we decided one-thread model, later all page cache locks
	 * can be removed
	 */
	memcpy(buf, pgc->cached_pages + ckoff, len);

	update_lirs_structure(pgc);

	return len;
}

/*
 * This function is barely called
 */
ssize_t __read_from_two_cachelines(struct lego_task_struct *tsk,
	struct lego_pgcache_file *file, char __user *buf, size_t count, loff_t *pos)
{
	/* Not userful at this time */
	struct lego_pgcache_struct *pgc1, *pgc2;
	ssize_t retval;
	int ret;
	loff_t ckoff_1;
	size_t len_1, len_2, cl_size;
	char *f_name = file->filepath;

	ret = prepare_two_cachelines(file, *pos, &retval, &pgc1, &pgc2);

	pgcache_debug("pgc1:%p, pgc2:%p, cacheline1:%p, cacheline2:%p",		\
			pgc1, pgc2, pgc1->cached_pages, pgc2->cached_pages);

	/* NOMEM for allocating cachelines */
	if(unlikely(!ret)) {
		return __storage_read(tsk, f_name, buf, count, pos);
	}

	BUG_ON(!pgc1 || !pgc2 || !pgc1->cached_pages || !pgc2->cached_pages);

	/* read from cacheline 1 */
	ckoff_1 = chunk_offset(*pos);
	cl_size = CL_SIZE;
	len_1 = cl_size - ckoff_1;

	BUG_ON(len_1 >= count);

	memcpy(buf, pgc1->cached_pages + ckoff_1, len_1);
	update_lirs_structure(pgc1);

	/* read from cacheline 2 */
	len_2 = count - len_1;
	memcpy(buf + len_1, pgc2->cached_pages, len_2);
	update_lirs_structure(pgc2);

	/* marshalling return value */
	if (pgc1->real_len < cl_size) {
		if (likely(pgc2->real_len == 0)) {
			retval = pgc1->real_len - ckoff_1;
			goto out;
		}
	} else {
		retval = len_1;
		if (likely(pgc2->real_len > len_2)) {
			retval += len_2;
			goto out;
		}
		retval += pgc2->real_len;
	}

out:
	return retval;
}

/*
 * lego_pgcache_read: load from storage side, perform pgcache read
 * caller: handle_p2m_read
 * @tsk: legacy, not useful, handle_p2m_read pass NULL
 * @f_name: full pathname of targetted file
 * @storage_node: hosted storage homenode
 * @buf: actually is from kernel space, is part of IB reply buffer
 * @pos: offset within the file
 * return value: read size.
 */
ssize_t lego_pgcache_read(struct lego_task_struct *tsk, char *f_name,
		unsigned int storage_node, char __user *buf, size_t count, loff_t *pos)
{
	unsigned int nr_cachelines;
	struct lego_pgcache_file *file;

	nr_cachelines = __nr_cachelines(*pos, count);

	BUG_ON(nr_cachelines > 2);

	file = find_lego_pgcache_file(f_name);
	if (!file) {
		file = lego_pgcache_file_open(f_name, storage_node);
		/* NO memory for allocating file struct and page cache */
		if (unlikely(IS_ERR(file))) {
			return -ENOMEM;
		}
		ht_insert_lego_pgcache_file(file);
	}

	if (likely(nr_cachelines == 1)) {
		return __read_from_one_cacheline(tsk, file, buf, count, pos);
	}

	/* two cachelines case */
	return __read_from_two_cachelines(tsk, file, buf, count, pos);
}

/* Write operations */

ssize_t __write_to_one_cacheline(struct lego_task_struct *tsk,
	struct lego_pgcache_file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct lego_pgcache_struct *pgc;
	loff_t ckoff;
	ssize_t retval;
	char *f_name = file->filepath;

	if (likely((*pos) % CL_SIZE == 0 && count == CL_SIZE))
		pgc = prepare_cacheline_fast(file, *pos, &retval);
	else
		pgc = prepare_cacheline(file, *pos, &retval);
	ckoff = chunk_offset(*pos);

	/* NOMEM for caching */
	if (unlikely(!pgc))
		return __storage_write(tsk, f_name, buf, count, pos);

	spin_lock(&pgc->lock);
	memcpy(pgc->cached_pages + ckoff, buf, count);

	/* Extend current real_len */
	if (ckoff + count > pgc->real_len) {
		pgc->real_len = ckoff + count;
	}
	spin_unlock(&pgc->lock);

	pgcache_debug("pgcache vaddr: %p, content: [%s]", pgc->cached_pages + ckoff,
			(char *) pgc->cached_pages + ckoff);

	/* add to dirty list */
	mark_lego_pgcache_dirty(pgc, file);
	update_lirs_structure(pgc);

	/* update file size */
	spin_lock(&file->dirtylist_lock);
	if (count + (*pos) > file->f_size) {
		file->f_size = count + (*pos);
	}
	spin_unlock(&file->dirtylist_lock);

	return count;
}

ssize_t __write_to_two_cachelines(struct lego_task_struct *tsk,
	struct lego_pgcache_file *file, char __user *buf, size_t count, loff_t *pos)
{
	struct lego_pgcache_struct *pgc1, *pgc2;
	ssize_t retval;
	int ret;
	loff_t ckoff_1;
	size_t len_1, len_2, cl_size;
	char *f_name = file->filepath;

	ret = prepare_two_cachelines(file, *pos, &retval, &pgc1, &pgc2);

	pgcache_debug("pgc1:%p, pgc2:%p, cacheline1:%p, cacheline2:%p",		\
			pgc1, pgc2, pgc1->cached_pages, pgc2->cached_pages);

	/* NOMEM for allocating cachelines */
	if(unlikely(!ret)) {
		return __storage_write(tsk, f_name, buf, count, pos);
	}

	BUG_ON(!pgc1 || !pgc2 || !pgc1->cached_pages || !pgc2->cached_pages);

	/* write to cacheline 1 */
	ckoff_1 = chunk_offset(*pos);
	cl_size = CL_SIZE;
	len_1 = cl_size - ckoff_1;

	BUG_ON(len_1 >= count);

	spin_lock(&pgc1->lock);
	memcpy(pgc1->cached_pages + ckoff_1, buf, len_1);

	/* extending pgc1 length to cl_size */
	if (pgc1->real_len < cl_size) {
		pgc1->real_len = cl_size;
	}
	spin_unlock(&pgc1->lock);

	mark_lego_pgcache_dirty(pgc1, file);
	update_lirs_structure(pgc1);


	/* read from cacheline 2 */
	len_2 = count - len_1;

	spin_lock(&pgc2->lock);
	memcpy(pgc2->cached_pages, buf + len_1, len_2);

	/* extending pgc2 length to len_2 */
	if (pgc2->real_len < len_2) {
		pgc1->real_len = len_2;
	}
	spin_unlock(&pgc2->lock);

	mark_lego_pgcache_dirty(pgc2, file);
	update_lirs_structure(pgc2);

	/* update file size */
	spin_lock(&file->dirtylist_lock);
	if (count + (*pos) > file->f_size) {
		file->f_size = count + (*pos);
	}
	spin_unlock(&file->dirtylist_lock);

	return count;
}

/*
 * lego_pgcache_write: load from storage side, perform pgcache write
 * caller: handle_p2m_write
 * @tsk: legacy, not useful, handle_p2m_write pass NULL
 * @f_name: full pathname of targetted file
 * @storage_node: hosted storage homenode
 * @buf: actually is from kernel space, is part of IB receive buffer
 * @pos: offset within the file
 * return value: write size.
 */
ssize_t lego_pgcache_write(struct lego_task_struct *tsk, char *f_name,
		unsigned int storage_node, char __user *buf, size_t count, loff_t *pos)
{
	unsigned int nr_cachelines;
	struct lego_pgcache_file *file;

	printk_once("cl_size = %lu\n", CL_SIZE);
	nr_cachelines = __nr_cachelines(*pos, count);

	BUG_ON(nr_cachelines > 2);

	file = find_lego_pgcache_file(f_name);
	if (!file) {
		file = lego_pgcache_file_open(f_name, storage_node);
		/* NO memory for allocating file struct and page cache */
		if (unlikely(IS_ERR(file))) {
			return -ENOMEM;
		}
		ht_insert_lego_pgcache_file(file);
	}

	if (likely(nr_cachelines == 1)) {
		return __write_to_one_cacheline(tsk, file, buf, count, pos);
	}

	/* two cachelines case */
	return __write_to_two_cachelines(tsk, file, buf, count, pos);
}
