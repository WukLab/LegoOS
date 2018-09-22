/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file describes all file-related syscall handlers
 */

#include <lego/slab.h>
#include <lego/kernel.h>
#include <lego/spinlock.h>
#include <lego/comp_memory.h>
#include <lego/fit_ibapi.h>
#include <lego/files.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/file_ops.h>
#include <memory/pgcache.h>
#include <memory/thread_pool.h>

#ifdef CONFIG_DEBUG_HANDLE_FILE
#define file_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
static inline void file_debug(const char *fmt, ...) { }
#endif

struct p2m_read_reply {
	/* nb of bytes read, or error */
	ssize_t		retval;

	/* the content */
	char		buf[0];
};

/*
 * OPCODE: P2M_READ
 * Handle a read() syscall request from processor
 */
void handle_p2m_read(struct p2m_read_write_payload *payload,
		     struct common_header *hdr, struct thpool_buffer *tb)
{
	loff_t pos = payload->offset;
	ssize_t count = payload->len;
	ssize_t retval;
	void *buf;
	struct p2m_read_reply *retbuf;
	struct lego_task_struct *tsk;

	file_debug("pid: %u tgid: %u buf: %p len: %zu, f_name: %s count: %zu",
		payload->pid, payload->tgid, payload->buf, payload->len,
		payload->filename, count);

	/*
	 * read() is dangerous here, because it may need a
	 * very large tx buffer. Currently, we have two insurance:
	 * - P side will chunk the read() based on THPOOL_TX_SIZE
	 * - tb_set_tx_size() will check against THPOOL_TX_SIZE
	 */
	retbuf = thpool_buffer_tx(tb);
	buf = (char *)retbuf + sizeof(retval);
	tb_set_tx_size(tb, sizeof(retval) + count);

	tsk = find_lego_task_by_pid(hdr->src_nid, payload->tgid);
	if (unlikely(!tsk)) {
		retbuf->retval = -ESRCH;
		return;
	}

#ifndef CONFIG_MEM_PAGE_CACHE
	retval = __storage_read(tsk, payload->filename, buf, count, &pos);
#else
	retval = lego_pgcache_read(NULL, payload->filename, STORAGE_NODE, buf, count, &pos);
#endif

	/*
	 * retval is the number of bytes be read
	 * or a negative value indicate error.
	 */
	retbuf->retval = retval;
}

/*
 * OPCODE: P2M_WRITE
 * Handle a write() syscall request from processor
 * ib_rx_buf:
 * [struct common_header][struct p2m_read_write_payload][write content]
 * |<-hdr                |<-payload                     |<-content
 * retrun 0 on success, -errno on fail
 */
void handle_p2m_write(struct p2m_read_write_payload *payload,
		      struct common_header *hdr, struct thpool_buffer *tb)
{
	struct lego_task_struct *tsk;
	ssize_t *retval;
	loff_t offset = payload->offset;
	void *content = (void *)payload + sizeof(*payload);

	file_debug("pid: %u tgid: %u buf: %p len: %zu, f_name: %s",
		payload->pid, payload->tgid, payload->buf, payload->len,
		payload->filename);

	retval = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*retval));

	tsk = find_lego_task_by_pid(hdr->src_nid, payload->tgid);
	if (unlikely(!tsk)){
		*retval = -ESRCH;
		return;
	}

#ifndef CONFIG_MEM_PAGE_CACHE
	*retval = __storage_write(tsk, payload->filename,
				  content, payload->len, &offset);
#else
	*retval = lego_pgcache_write(NULL, payload->filename,
				     STORAGE_NODE, content,
				     payload->len, &offset);
#endif
}

int handle_p2m_close(struct p2m_close_struct *payload, u64 desc,
		struct common_header *hdr)
{
	WARN_ON(1);
	return 0;
}

void handle_p2m_drop_page_cache(struct common_header *hdr, struct thpool_buffer *tb)
{
	int *retval;

	retval = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*retval));

#ifndef CONFIG_MEM_PAGE_CACHE
	*retval = -EIO;
#else
	*retval = drop_pgcache();
#endif
}
