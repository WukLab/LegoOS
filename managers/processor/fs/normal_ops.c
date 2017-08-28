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

#include "internal.h"


static int normal_p2s_open(struct file *f)
{
	/* opcode + payload */
	__u32 *opcode;
	struct m2s_open_payload *payload;
	u32 len_msg = sizeof(__u32) + sizeof(struct m2s_open_payload);
	void *msg;
	int retval = 0;
	char *err;

	msg = kmalloc(len_msg, GFP_KERNEL);

	opcode = (__u32 *) msg;
	payload = (struct m2s_open_payload *) (msg + sizeof(__u32));

	*opcode = M2S_OPEN;

	payload->uid = current_uid(); //?
	strcpy(payload->filename, f->f_name);
	payload->permission = f->f_mode;
	payload->flags = f->f_flags; 

#ifdef DEBUG_STORAGE
	pr_info("normal_p2s_open : [%s]\n", payload->filename);
	pr_info("normal_p2s_open : mode -> [0%o]\n", payload->permission);
	pr_info("normal_p2s_open : flags -> [0x%x]\n", payload->flags);
	pr_info("normal_p2s_open : check pointer address : \n");
	pr_info("msg : %p, payload : %p\n", msg, payload);
	pr_info("payload->uid : %x, payload->filename : %s\n", payload->uid, payload->filename);
	pr_info("payload->permission : %x, payload->flags : %x\n", payload->permission, payload->flags);
#endif
	
	//net_send_reply(STORAGE_NODE, M2S_OPEN, &payload, sizeof(payload),
		  //&retval, sizeof(retval), false);
	ibapi_send_reply_imm(STORAGE_NODE, msg, len_msg, &retval, sizeof(retval), false);

	kfree(msg);
#ifdef DEBUG_STORAGE
	err =  ret_to_string(ERR_TO_LEGO_RET((long)retval));
	pr_info("normal_p2s_open : %s\n", err);
#endif
	return retval;
}

/* we need to pass user buf virtual address to memory component  
 *
 */

static ssize_t normal_p2s_read(struct file *f, char __user *buf,
				size_t count, loff_t *off) {
	/* retbuf should only put in memory side */
	ssize_t retval = 0;

	void *msg;
	/* common_header + p2m_read_write_payload */
	u32 len_msg = sizeof(struct common_header) + sizeof(struct p2m_read_write_payload);
	
	struct common_header *hdr;
	struct p2m_read_write_payload *payload;

	msg = kmalloc(len_msg, GFP_KERNEL);
	hdr = (struct common_header *) msg;
	payload = (struct p2m_read_write_payload *) (msg + sizeof(struct common_header));

	hdr->opcode = M2S_READ;
	hdr->src_nid = LEGO_LOCAL_NID;
	hdr->length = len_msg;

	payload->pid = current->pid;
	payload->buf = buf;

	payload->uid = current_uid();/* should be user uid */
	strcpy(payload->filename, f->f_name);
	payload->flags = f->f_flags;
	payload->len = count;
	payload->offset = (*off);

	ibapi_send_reply_imm(DEF_MEM_HOMENODE, msg, len_msg, &retval, sizeof(retval), false);

	if(retval >= 0){
		*off += retval;
	}

	if (retval < 0){
#ifdef DEBUG_STORAGE
		char *err;
		err = ret_to_string(ERR_TO_LEGO_RET((long)retval));
		pr_info("%s\n", err);		
#endif
	}
	
	return retval;
}

static ssize_t normal_p2s_write(struct file *f, const char __user *buf,
				size_t count, loff_t *off)
{
	void *msg;
	/* common_header + p2s_read_write_payload */
	u32 len_msg = sizeof(struct common_header) + sizeof(struct p2m_read_write_payload);

	struct common_header *hdr;
	struct p2m_read_write_payload *payload;

	/* retbuf should only contain a retval */

	ssize_t retval = 0;

	msg = kmalloc(len_msg, GFP_KERNEL);
	hdr = (struct common_header *) msg;
	payload = (struct p2m_read_write_payload *) (msg + sizeof(struct common_header));

	hdr->opcode = M2S_WRITE;
	hdr->src_nid = LEGO_LOCAL_NID;
	hdr->length = len_msg;

	payload->pid = current->pid;
	payload->buf = (char *)buf;

	payload->uid = current_uid(); /* should be user uid */
	strcpy(payload->filename, f->f_name);
	payload->flags = f->f_flags;
	payload->len = count;
	payload->offset = (*off);

	ibapi_send_reply_imm(DEF_MEM_HOMENODE, msg, len_msg, &retval, sizeof(retval), false);

	if(retval >= 0){
		*off += retval;
	}

	if(retval < 0){
#ifdef DEBUG_STORAGE
		char *err;
		err = ret_to_string(ERR_TO_LEGO_RET((long)retval));
		pr_info("%s\n", err);		
#endif
	}
	return retval;
}

struct file_operations normal_p2s_f_ops = {
	.open = normal_p2s_open,
	.read = normal_p2s_read,
	.write = normal_p2s_write,
};


#ifdef KERNEL_P2S_TEST

#define O_CREAT		00000100
#define O_WRONLY	00000001
#define O_RDONLY 	00000000
#define O_RDWR		00000002

void p2s_test(){
	struct file *f;
	ssize_t ret;
	char __user *buf;

	f = kmalloc(sizeof(struct file), GFP_KERNEL);
	f->f_mode = 0744;
	f->f_flags = O_WRONLY | O_CREAT;
	strcpy(f->f_name, "/root/yilun/test_lego_file");

	pr_info("before sending normal open request\n");	
	ret = normal_p2s_open(f);
	pr_info("received reply, retval is [%d]\n", ret);

	loff_t off = 0;
	pr_info("test p2s_write.\n");
	normal_p2s_write(f, buf, 10, &off);
	pr_info("done test write, off value now is [%ld].\n", off);

	off = 0;
	pr_info("test read.\n");
	normal_p2s_read(f, buf, 7, &off);
	pr_info("test read received [%s], off value now is [%ld]\n", buf, off);

	kfree(f);
}
#endif

SYSCALL_DEFINE3(lseek, unsigned int, fd, off_t, offset, unsigned int, whence)
{
	struct file *f = fdget(fd);
	if(IS_ERR(f))
		return -EBADF;

	/* XXX: seq_lseek is wrong */
	return seq_lseek(f, offset, whence);
}
