/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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

#include <memory/include/vm.h>
#include <memory/include/pid.h>
#include <memory/include/file_ops.h>

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
	retval = __storage_read(tsk, payload->filename, buf, count, &pos);
	if (retval < 0) {
		kfree(retbuf);
		goto err_reply;
	}

	/* Succeed */
	ibapi_reply_message(retbuf, count + sizeof(retval), desc);

	kfree(retbuf);
	return 0;

err_reply:
	/* Error, only reply 8 bytes */
	ibapi_reply_message(&retval, sizeof(ssize_t), desc);
	return 0;
}

static ssize_t m2s_write(void *p2m_void_payload, struct lego_task_struct *tsk)
{
#if 0
	struct p2m_read_write_payload *payload = 
		(struct p2m_read_write_payload *) p2m_void_payload;
	void *msg;
	u32 len_msg;
	ssize_t retval = 0;

	__u32 *opcode;
	struct m2s_read_write_payload *payload;
	char *content;

	/* msg = opcode + payload + content */
	len_msg = sizeof(__u32) +  sizeof(struct m2s_read_write_payload)
	       	+ payload->len;

	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		return -ENOMEM;		
	}
	
	opcode = (__u32 *) msg;
	payload = (struct m2s_read_write_payload *) (msg + sizeof(__u32));
	content = (char *) (msg + sizeof(__u32) + 
			sizeof(struct m2s_read_write_payload));

	*opcode = M2S_WRITE;

	payload->uid = payload->uid;
	strcpy(payload->filename, payload->filename);
	payload->flags = payload->flags;
	payload->len = payload->len;
	payload->offset = payload->offset;

#ifdef DEBUG_STORAGE
	pr_info("m2s_write : payload info : \n");
	pr_info("filename : %s\n", payload->filename);
	pr_info("uid : %d, flags : %d, len : %zu, offset : %lld\n",
			payload->uid, payload->flags, payload->len, payload->offset);
#endif

	memcpy(content, p2m_void_payload + sizeof(struct p2m_read_write_payload),
		       	payload->len); 

	ibapi_send_reply_imm(STORAGE_NODE, msg, len_msg, &retval,
			sizeof(retval), false);

	kfree(msg);
	return retval;
#endif
	BUG();
	return 0;
}

/*
 * OPCODE: P2M_WRITE
 * Handle a write() syscall request from processor
 */
int handle_p2m_write(struct p2m_read_write_payload *payload, u64 desc,
		     struct common_header *hdr)
{
	struct lego_task_struct *tsk;
	ssize_t retval;

	file_debug("pid: %u tgid: %u buf: %#lx len: %zu, f_name: %s",
		payload->pid, payload->tgid, payload->buf, payload->len,
		payload->filename);

	tsk = find_lego_task_by_pid(hdr->src_nid, payload->tgid);
	if (unlikely(!tsk)){
		retval = -ESRCH;
		goto out_reply;
	}

	retval = m2s_write(payload, tsk);

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
