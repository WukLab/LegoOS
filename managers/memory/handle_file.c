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

#ifdef CONFIG_DEBUG_HANDLE_FILE
#define file_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
static inline void file_debug(const char *fmt, ...) { }
#endif

/*
 * OPCODE: P2M_READ
 * Handle a read() syscall request from processor
 */
int handle_p2m_read(struct p2m_read_write_payload *payload, u64 desc,
		    struct common_header *hdr)
{
	loff_t pos = payload->offset;
	ssize_t count = payload->len;
	ssize_t retval;
	void *retbuf, *buf;
	struct lego_task_struct *tsk;

	file_debug("pid: %u tgid: %u buf: %p len: %zu, f_name: %s",
		payload->pid, payload->tgid, payload->buf, payload->len,
		payload->filename);

	tsk = find_lego_task_by_pid(hdr->src_nid, payload->tgid);
	if (unlikely(!tsk)) {
		retval = -ESRCH;
		goto err_reply;
	}

	retbuf = kmalloc(count + sizeof(retval), GFP_KERNEL);
	if (!retbuf) {
		retval = -ENOMEM;
		goto err_reply;
	}

	buf = retbuf + sizeof(retval);

#ifndef CONFIG_MEM_PAGE_CACHE
	retval = __storage_read(tsk, payload->filename, buf, count, &pos);
#else
	retval = lego_pgcache_read(NULL, payload->filename, STORAGE_NODE, buf, count, &pos);
#endif

	if (retval < 0) {
		kfree(retbuf);
		goto err_reply;
	}

	/*
	 * The first 8 bytes is nr of bytes be read
	 * We really need a structure to fill this.
	 * This is hard to code and debug.
	 */
	*(ssize_t *)retbuf = retval;

	/* Succeed */
	ibapi_reply_message(retbuf, count + sizeof(retval), desc);

	kfree(retbuf);
	return 0;

err_reply:
	/* Error, only reply 8 bytes */
	ibapi_reply_message(&retval, sizeof(ssize_t), desc);
	return 0;
}

/*
 * OPCODE: P2M_WRITE
 * Handle a write() syscall request from processor
 * ib_rx_buf:
 * [struct common_header][struct p2m_read_write_payload][write content]
 * |<-hdr                |<-payload                     |<-content
 * retrun 0 on success, -errno on fail
 */
int handle_p2m_write(struct p2m_read_write_payload *payload, u64 desc,
		     struct common_header *hdr)
{
	struct lego_task_struct *tsk;
	ssize_t retval;
	loff_t offset = payload->offset;
	void *content = (void *)payload + sizeof(*payload);

	file_debug("pid: %u tgid: %u buf: %p len: %zu, f_name: %s",
		payload->pid, payload->tgid, payload->buf, payload->len,
		payload->filename);

	tsk = find_lego_task_by_pid(hdr->src_nid, payload->tgid);
	if (unlikely(!tsk)){
		retval = -ESRCH;
		goto out_reply;
	}

#ifndef CONFIG_MEM_PAGE_CACHE
	retval = __storage_write(tsk, payload->filename,
				content, payload->len, &offset);
#else
	retval = lego_pgcache_write(NULL, payload->filename, STORAGE_NODE, content,
			payload->len, &offset);
#endif

out_reply:
	ibapi_reply_message(&retval, sizeof(retval), desc);
	return retval;
}

int handle_p2m_close(struct p2m_close_struct *payload, u64 desc,
		struct common_header *hdr)
{
	WARN_ON(1);
	return 0;
}
