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

#include <lego/timer.h>
#include <lego/fit_ibapi.h>

#include "internal.h"


static int normal_p2s_open(struct file *f)
{
	/* opcode + payload */
	u32 len_msg = sizeof(__u32) + sizeof(struct m2s_open_payload);
	void *msg;
	msg = kmalloc(len_msg, GFP_KERNEL);

	__u32 *opcode;
	struct m2s_open_payload *payload;
	opcode = (__u32 *) msg;
	payload = (struct m2s_open_payload *) (msg + sizeof(__u32));

	*opcode = M2S_OPEN;

	payload->uid = current_uid(); //?
	strcpy(payload->filename, f->f_name);
	payload->permission = f->f_mode;
	payload->flags = f->f_flags; 

	int retval;

#ifdef DEBUG_STORAGE
	pr_info("normal_p2s_open : [%s]\n", payload->filename);
	pr_info("normal_p2s_open : mode -> [0%o]\n", payload->permission);
	pr_info("normal_p2s_open : flags -> [0x%x]\n", payload->flags);
	pr_info("normal_p2s_open : check pointer address : \n");
	pr_info("msg : %lu, payload : %lu\n", msg, payload);
	pr_info("payload->uid : %lu, payload->filename : %lu\n", &payload->uid, payload->filename);
	pr_info("payload->permission : %lu, payload->flags : %lu\n", &payload->permission, &payload->flags);
#endif
	
	//net_send_reply(STORAGE_NODE, M2S_OPEN, &payload, sizeof(payload),
		  //&retval, sizeof(retval), false);
	ibapi_send_reply_imm(STORAGE_NODE, msg, len_msg, &retval, sizeof(retval), false);

	kfree(msg);
#ifdef DEBUG_STORAGE
	char *err;
	err =  ret_to_string(ERR_TO_LEGO_RET((long)retval));
	pr_info("normal_p2s_open : %s\n", err);
#endif
	return retval;
}

/* we need to pass user buf virtual address to memory component  
 *
 */

static ssize_t normal_p2s_read(struct file *f, char __user *buf,
				size_t count, loff_t *off){
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

	/* retbuf should only put in memory side */
	ssize_t retval;

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

static ssize_t normal_p2s_write(struct file *f, char __user *buf,
				size_t count, loff_t *off){
	void *msg;
	/* common_header + p2s_read_write_payload */
	u32 len_msg = sizeof(struct common_header) + sizeof(struct p2m_read_write_payload);

	struct common_header *hdr;
	struct p2m_read_write_payload *payload;

	msg = kmalloc(len_msg, GFP_KERNEL);
	hdr = (struct common_header *) msg;
	payload = (struct p2m_read_write_payload *) (msg + sizeof(struct common_header));

	hdr->opcode = M2S_WRITE;
	hdr->src_nid = LEGO_LOCAL_NID;
	hdr->length = len_msg;

	payload->pid = current->pid;
	payload->buf = buf;

	payload->uid = current_uid(); /* should be user uid */
	strcpy(payload->filename, f->f_name);
	payload->flags = f->f_flags;
	payload->len = count;
	payload->offset = (*off);

	/* retbuf should only contain a retval */

	ssize_t retval;

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

/*static ssize_t normal_m2s_read(struct file *f, char __user *buf,
				size_t count, loff_t *off)
{
	struct m2s_read_write_payload payload;
	payload.uid = current_uid(); //?
	strcpy(payload.filename, f->f_name);
	payload.flags = f->f_flags;
	payload.len = count;
	payload.offset = (*off);
 
	ssize_t retval;
	ssize_t *retval_in_buf;
	void *retbuf;

	retbuf = kmalloc(sizeof(retval)+count, GFP_KERNEL);

	net_send_reply(STORAGE_NODE, M2S_READ, &payload, sizeof(payload),
		   	&retbuf, sizeof(retbuf), false);

	copy_to_user(buf, retbuf+sizeof(retval), count);
	retval_in_buf = (ssize_t *) retbuf;

	retval = *retval_in_buf;

	kfree(retbuf);

	return retval;
}

static ssize_t normal_m2s_write(struct file *f, const char __user *buf,
				 size_t count, loff_t *off)
{
	void *m2s_write_payload;
	m2s_write_payload = kmalloc(sizeof(struct m2s_read_write_payload)+count, GFP_KERNEL);

	struct m2s_read_write_payload *payload;
	payload = (struct m2s_read_write_payload *) m2s_write_payload;
	payload->uid = current_uid(); //?
	strcpy(payload->filename, f->f_name);
	payload->flags = f->f_flags;
	payload->len = count;
	payload->offset = (*off);

	copy_from_user(m2s_write_payload + sizeof(payload), buf, count);

	ssize_t retval;

	net_send_reply(STORAGE_NODE, M2S_WRITE, &m2s_write_payload, sizeof(m2s_write_payload),
		   	&retval, sizeof(retval), false);

	kfree(m2s_write_payload);

	return retval;
}*/

#define O_CREAT		00000100
#define O_WRONLY	00000001
#define O_RDONLY 	00000000
#define O_RDWR		00000002

/*static ssize_t test_m2s_read(struct file *f, char *buf,
				size_t count, loff_t *off)
{
	u32 len_msg;
	void *msg;

	// opcode + payload
	len_msg = sizeof(__u32) + sizeof(struct m2s_read_write_payload);
	msg = kmalloc(len_msg, GFP_KERNEL);

	__u32 *opcode;
	struct m2s_read_write_payload *payload;
	opcode = (__u32 *) msg;
	payload = (struct m2s_read_write_payload *) (msg + sizeof(__u32));

	*opcode = M2S_READ;

	payload->uid = current_uid();
	strcpy(payload->filename, f->f_name);
	payload->flags = f->f_flags;
	payload->len = count;
	payload->offset = (*off);

	ssize_t retval;
	ssize_t *retval_in_buf;
	void *retbuf;

	// retbuf = retval + content
	u32 len_ret = sizeof(retval) + count;
	retbuf = kmalloc(len_ret, GFP_KERNEL);

	//net_send_reply(STORAGE_NODE, M2S_READ, &payload, sizeof(payload),
		   	//retbuf, sizeof(retbuf), false);
	ibapi_send_reply_imm(STORAGE_NODE, msg, len_msg, retbuf, len_ret, false);

	memcpy(buf, retbuf+sizeof(retval), count);
	pr_info("buf[0-2] : %c %c %c\n", buf[0], buf[1], buf[2]);
	retval_in_buf = (ssize_t *) retbuf;

	retval = *retval_in_buf;

	kfree(msg);
	kfree(retbuf);
	(*off) += retval;

	return retval;
}

static ssize_t test_m2s_write(struct file *f, const char *buf,
				 size_t count, loff_t *off)
{
	void *msg;
	u32 len_msg;

	// msg = opcode + payload + content
	len_msg = sizeof(__u32) +  sizeof(struct m2s_read_write_payload) + count;
	msg = kmalloc(len_msg, GFP_KERNEL);

	__u32 *opcode;
	struct m2s_read_write_payload *payload;
	char *content;
	
	opcode = (__u32 *) msg;
	payload = (struct m2s_read_write_payload *) (msg + sizeof(__u32));
	content = (char *) (msg + sizeof(__u32) + sizeof(struct m2s_read_write_payload));

	*opcode = M2S_WRITE;

	payload->uid = current_uid(); //?
	strcpy(payload->filename, f->f_name);
	payload->flags = f->f_flags;
	payload->len = count;
	payload->offset = (*off);

	memcpy(content, buf, count);

	pr_info("test_m2s_write.\n");
	pr_info("payload uid [%d].\n", payload->uid);
	pr_info("payload filename [%s].\n", payload->filename);
	pr_info("payload flags [%o].\n", payload->flags);
	pr_info("payload len [%u].\n", payload->len);
	pr_info("payload offset [%ld].\n", payload->offset);

	pr_info("content is [%s].\n", content);

	ssize_t retval;

	//net_send_reply(STORAGE_NODE, M2S_WRITE, m2s_write_payload, len_msg,
		   //&retval, sizeof(retval), false);
	
	ibapi_send_reply_imm(STORAGE_NODE, msg, len_msg, &retval, sizeof(retval), false);

	kfree(msg);
	(*off) += retval;

	return retval;
}*/

void p2s_test(){
	struct file *f;
	f = kmalloc(sizeof(struct file), GFP_KERNEL);
	f->f_mode = 0744;
	f->f_flags = O_WRONLY | O_CREAT;
	strcpy(f->f_name, "/root/yilun/test_lego_file");

	ssize_t ret;

	pr_info("before sending normal open request\n");	
	ret = normal_p2s_open(f);
	pr_info("received reply, retval is [%d]\n", ret);

	char __user *buf;
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

