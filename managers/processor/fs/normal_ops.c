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
#include <lego/comp_processor.h>
#include <lego/comp_common.h>
#include <lego/comp_storage.h>
#include <lego/seq_file.h>
#include <lego/timer.h>
#include <lego/fit_ibapi.h>

#include <processor/include/fs.h>

#ifdef CONFIG_DEBUG_FILE
#define file_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
static inline void file_debug(const char *fmt, ...) { }
#endif

/*
 * p2s_open:
 * Send request to storage directly.
 */
static int normal_p2s_open(struct file *f)
{
	int retval = 0;
	void *msg;
	u32 len_msg, *opcode;
	struct p2s_open_struct *payload;

	len_msg = sizeof(*opcode) + sizeof(*payload);
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	opcode = msg;
	*opcode = P2S_OPEN;

	payload = msg + sizeof(*opcode);
	payload->uid = current_uid();
	strcpy(payload->filename, f->f_name);
	payload->permission = f->f_mode;
	payload->flags = f->f_flags;

	file_debug("f_name: %s, mode: 0%o, flags: %x",
		payload->filename, payload->permission, payload->flags);

	ibapi_send_reply_imm(STORAGE_NODE, msg, len_msg, &retval, sizeof(retval), false);
	if (retval < 0)
		pr_debug("%s: %s\n", FUNC, ret_to_string(ERR_TO_LEGO_RET((long)retval)));

	kfree(msg);
	return retval;
}

/*
 * p2m_read
 * Send request to memory manager
 */
static ssize_t normal_p2m_read(struct file *f, char __user *buf,
			       size_t count, loff_t *off)
{
	ssize_t retval, retlen;
	ssize_t *retval_ptr;
	u32 len_retbuf, len_msg;
	void *retbuf, *msg, *content;
	struct common_header *hdr;
	struct p2m_read_write_payload *payload;

	len_retbuf = sizeof(ssize_t) + count;
	retbuf = kmalloc(len_retbuf, GFP_KERNEL);
	if (!retbuf)
		return -ENOMEM;

	len_msg = sizeof(*hdr) + sizeof(*payload);
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (!msg) {
		kfree(retbuf);
		return -ENOMEM;
	}

	/* Construct payload */
	hdr = msg;
	hdr->opcode = P2M_READ;
	hdr->src_nid = LEGO_LOCAL_NID;
	hdr->length = len_msg;

	payload = msg + sizeof(*hdr);
	payload->pid = current->pid;
	payload->tgid = current->tgid;
	payload->buf = buf;
	payload->uid = current_uid();
	strncpy(payload->filename, f->f_name, MAX_FILENAME_LENGTH);
	payload->flags = f->f_flags;
	payload->len = count;
	payload->offset = *off;

	retlen = ibapi_send_reply_imm(DEF_MEM_HOMENODE, msg, len_msg,
				      retbuf, len_retbuf, false);
	if (unlikely(retlen == sizeof(ssize_t))) {
		retval = *(ssize_t *)retbuf;
		file_debug("%s", ret_to_string(ERR_TO_LEGO_RET(retval)));
		goto out;
	} else if (unlikely(retlen > len_retbuf)) {
		panic("BUG: retlen: %zu, len_retbuf: %u\n",
				retlen, len_retbuf);
	}

	/*
	 * The first 8 bytes stores the nr of bytes been read
	 * The left is the real content
	 */
	retval_ptr = retbuf;
	retval = *retval_ptr;
	content = retbuf + sizeof(ssize_t);

	/* If success, we copy the content into user's cacheline */
	if (likely(retval >= 0)) {
#ifdef CONFIG_DEBUG_FILE
		print_hex_dump_bytes("Read Content: ", DUMP_PREFIX_ADDRESS, content, retval);
#endif
		*off += retval;
		if (copy_to_user(buf, content, count)) {
			retval = -EFAULT;
			goto out;
		}
	} else {
		/* should only got 8 bytes return buffer */
		BUG();
	}

out:
	file_debug("retval: %zu", retval);
	kfree(msg);
	kfree(retbuf);
	return retval;
}

static ssize_t normal_p2m_write(struct file *f, const char __user *buf,
				size_t count, loff_t *off)
{
	ssize_t retval, retlen;
	u32 len_msg;
	void *msg, *content;
	struct common_header *hdr;
	struct p2m_read_write_payload *payload;

	len_msg = sizeof(*hdr) + sizeof(*payload) + count;
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	/* Construct payload */
	hdr = (struct common_header *)msg;
	hdr->opcode = P2M_WRITE;
	hdr->src_nid = LEGO_LOCAL_NID;
	hdr->length = len_msg;

	payload = (struct p2m_read_write_payload *)(msg + sizeof(*hdr));
	payload->pid = current->pid;
	payload->tgid = current->tgid;
	payload->buf = (char *)buf;
	payload->uid = current_uid();
	payload->flags = f->f_flags;
	payload->len = count;
	payload->offset = (*off);
	strncpy(payload->filename, f->f_name, MAX_FILENAME_LENGTH);

	/* Copy the contents into the payload */
	content = msg + sizeof(*hdr) + sizeof(*payload);
	if (copy_from_user(content, buf, count)) {
		retval = -EFAULT;
		goto out;
	}

	/* Send to memory home node */
	retlen = ibapi_send_reply_imm(DEF_MEM_HOMENODE, msg, len_msg,
			&retval, sizeof(retval), false);
	if (unlikely(retlen != sizeof(retval))) {
		WARN_ON(1);
		retval = -EIO;
		goto out;
	}

	if (retval >= 0)
		*off += retval;

out:
	file_debug("retval: %zu", retval);
	kfree(msg);
	return retval;
}

struct file_operations normal_p2s_f_ops = {
	.open	= normal_p2s_open,
	.read	= normal_p2m_read,
	.write	= normal_p2m_write,
};

SYSCALL_DEFINE3(lseek, unsigned int, fd, off_t, offset, unsigned int, whence)
{
	struct file *f = fdget(fd);
	if(IS_ERR(f))
		return -EBADF;

	/* XXX: seq_lseek is wrong */
	return seq_lseek(f, offset, whence);
}
