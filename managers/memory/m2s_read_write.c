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
#include <lego/files.h>
#include <lego/kernel.h>
#include <lego/uaccess.h>
#include <lego/fit_ibapi.h>
#include <lego/comp_memory.h>
#include <lego/comp_common.h>
#include <lego/comp_storage.h>

#include <memory/include/pid.h>
#include <memory/include/vm.h>

static ssize_t storage_read(struct lego_task_struct *tsk,
			    struct lego_file *file,
			    char __user *buf, size_t count, loff_t *pos)
{
	u32 len_msg, len_ret, *opcode;
	void *msg, *retbuf, *content;
	ssize_t retval, *retval_in_buf;
	struct m2s_read_write_payload *payload;

	/* opcode + payload*/
	len_msg = sizeof(*opcode) + sizeof(*payload);
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	opcode = msg;
	*opcode = M2S_READ;

	payload = (msg + sizeof(u32));
	payload->uid = current_uid();
	strncpy(payload->filename, file->filename, MAX_FILENAME_LENGTH);
	payload->flags = O_RDONLY;
	payload->len = count;
	payload->offset = *pos;

	/* retbuf = retval + content */
	len_ret = sizeof(retval) + count;
	retbuf = kmalloc(len_ret, GFP_KERNEL);
	if(!retbuf) {
		kfree(msg);
		return -ENOMEM;
	}

	ibapi_send_reply_imm(STORAGE_NODE, msg, len_msg, retbuf, len_ret, false);

	retval_in_buf = (ssize_t *)retbuf;
	content = retbuf + sizeof(ssize_t);

	retval = *retval_in_buf;

	/* now copy content to __user buf */
	lego_copy_to_user(current, buf, content, count);

	kfree(msg);
	kfree(retbuf);
	return retval;	
}

static ssize_t storage_write(struct lego_task_struct *tsk, struct lego_file *file,
		const char *buf, size_t count, loff_t *pos)
{
	return -EINVAL;
}

static int storage_vma_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct lego_task_struct *tsk;
	struct lego_file *file;
	size_t count;
	loff_t pos;
	unsigned long page;

	page = __get_free_page(GFP_KERNEL);
	if (unlikely(!page))
		return VM_FAULT_OOM;

	tsk = vma->vm_mm->task;
	file = vma->vm_file;
	count = PAGE_SIZE;
	pos = vmf->pgoff << PAGE_SHIFT;

	storage_read(tsk, file, (char *)page, count, &pos);

	vmf->page = page;

	return 0;
}

static struct vm_operations_struct storage_vma_ops = {
	.fault = &storage_vma_fault,
};

static int storage_mmap(struct lego_task_struct *tsk, struct lego_file *file,
		      struct vm_area_struct *vma)
{
	vma->vm_ops = &storage_vma_ops;
	return 0;
}

struct lego_file_operations storage_file_ops = {
	.read	= storage_read,
	.write	= storage_write,
	.mmap	= storage_mmap,
};

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

	payload->uid = current_uid(); //?
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
	if (retval >= 0)
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
	
	ibapi_send_reply_imm(STORAGE_NODE, msg, len_msg, &retval, 
			sizeof(retval), false);

	kfree(msg);
	
	if (retval >= 0)
		(*off) += retval;

	return retval;
}*/

static ssize_t m2s_write(void *p2m_void_payload, 
			    struct lego_task_struct *tsk)
{
	struct p2m_read_write_payload *p2m_payload = 
		(struct p2m_read_write_payload *) p2m_void_payload;
	void *msg;
	u32 len_msg;
	ssize_t retval = 0;

	__u32 *opcode;
	struct m2s_read_write_payload *payload;
	char *content;

	/* msg = opcode + payload + content */
	len_msg = sizeof(__u32) +  sizeof(struct m2s_read_write_payload)
	       	+ p2m_payload->len;

	msg = kmalloc(len_msg, GFP_KERNEL);
	if (unlikely(!msg)) {
		WARN_ON(1);
		return -ENOMEM;		
	}
	
	opcode = (__u32 *) msg;
	payload = (struct m2s_read_write_payload *) (msg + sizeof(__u32));
	content = (char *) (msg + sizeof(__u32) + 
			sizeof(struct m2s_read_write_payload));

	*opcode = M2S_WRITE;

	payload->uid = p2m_payload->uid;
	strcpy(payload->filename, p2m_payload->filename);
	payload->flags = p2m_payload->flags;
	payload->len = p2m_payload->len;
	payload->offset = p2m_payload->offset;

#ifdef DEBUG_STORAGE
	pr_info("m2s_write : payload info : \n");
	pr_info("filename : %s\n", payload->filename);
	pr_info("uid : %d, flags : %d, len : %zu, offset : %lld\n",
			payload->uid, payload->flags, payload->len, payload->offset);
#endif

	/* now copy the user buf to content;
	 */
	//lego_copy_from_user(tsk, content, p2m_payload->buf, payload->len);
	memcpy(content, p2m_void_payload + sizeof(struct p2m_read_write_payload),
		       	p2m_payload->len); 
	//memcpy(content, buf, count);

	ibapi_send_reply_imm(STORAGE_NODE, msg, len_msg, &retval,
			sizeof(retval), false);

#ifdef DEBUG_STORAGE
	pr_info("content string is [%s]\n", content);
	if (retval < 0){
		char *err;
		err = ret_to_string(ERR_TO_LEGO_RET((long)retval));
		pr_info("m2s_write err : %s\n", err);
	}
#endif

	kfree(msg);
	return retval;
}

//static ssize_t m2s_read(struct p2m_read_write_payload *p2m_payload,
//				struct lego_task_struct *tsk)
static void *m2s_read(struct p2m_read_write_payload *p2m_payload,
				struct lego_task_struct *tsk)
{
	u32 len_msg;
	void *msg;
	__u32 *opcode;
	struct m2s_read_write_payload *payload;

	ssize_t retval;
	ssize_t *retval_in_buf;
	void *retbuf;
	char *content;
	u32 len_ret;

	/* opcode + payload*/
	len_msg = sizeof(__u32) + sizeof(struct m2s_read_write_payload);
	msg = kmalloc(len_msg, GFP_KERNEL);

	opcode = (__u32 *) msg;
	payload = (struct m2s_read_write_payload *) (msg + sizeof(__u32));

	*opcode = M2S_READ;

	payload->uid = p2m_payload->uid;
	strcpy(payload->filename, p2m_payload->filename);
	payload->flags = p2m_payload->flags;
	payload->len = p2m_payload->len;
	payload->offset = p2m_payload->offset;

#ifdef DEBUG_STORAGE
	pr_info("m2s_read : payload info : \n");
	pr_info("filename : %s\n", payload->filename);
	pr_info("uid : %d, flags : %d, len : %zu, offset : %lld\n",
			payload->uid, payload->flags, payload->len, payload->offset);
#endif


	/* retbuf = retval + content*/
	len_ret = sizeof(retval) + payload->len;
	retbuf = kmalloc(len_ret, GFP_KERNEL);

	ibapi_send_reply_imm(STORAGE_NODE, msg, len_msg, retbuf, len_ret, false);

	retval_in_buf = (ssize_t *) retbuf;
	content = (char *) (retbuf + sizeof(ssize_t));
#ifdef DEBUG_STORAGE
	pr_info("content string is [%s]\n", content);
	if (*retval_in_buf < 0){
		char *err;
		err = ret_to_string(ERR_TO_LEGO_RET((long) (*retval_in_buf)));
		pr_info("m2s_read err : %s\n", err);
	}

#endif

	retval = *retval_in_buf;
	/* now copy content to __user buf */
	lego_copy_to_user(tsk, p2m_payload->buf, content, payload->len);

	kfree(msg);
	//kfree(retbuf);

	//return retval;
	return retbuf;
}


/* payload do not contain opcode 
 * p2m_payload is same as payload for read
 */

ssize_t handle_p2s_read(void *payload, uintptr_t desc, struct common_header *hdr)
{
	struct p2m_read_write_payload *p2m_payload;
	struct lego_task_struct *tsk;
	ssize_t retval = 0;

	/* new added */
	void *retbuf;
	ssize_t *retval_in_buf;

	pr_info("handle_p2s_read\n");

	p2m_payload = (struct p2m_read_write_payload *) payload;

	tsk = find_lego_task_by_pid(hdr->src_nid, p2m_payload->pid);
	if (unlikely(!tsk)){
		/* No such process */
		retval = -ESRCH;
		retbuf = &retval;
		goto out_reply;
	}

#ifdef DEBUG_STORAGE
	pr_info("handle_p2s_read : find task_struct, pid : %d", p2m_payload->pid);
#endif

	//retval = m2s_read(p2m_payload, tsk);
	retbuf = m2s_read(p2m_payload, tsk);
	retval_in_buf = (ssize_t *) retbuf;
	retval =  *retval_in_buf;

out_reply:
	//ibapi_reply_message(&retval, sizeof(retval), desc);
	ibapi_reply_message(retbuf, sizeof(ssize_t)+p2m_payload->len, desc);
	//kfree(retbuf);
	return retval;
}

/* payload do not contain opcode
 * p2m_payload is also same as payload
 */
ssize_t handle_p2s_write(void *payload, uintptr_t desc, struct common_header *hdr)
{
	struct p2m_read_write_payload *p2m_payload;
	struct lego_task_struct *tsk;
	
	ssize_t retval;

	pr_info("handle_p2s_write\n");

	p2m_payload = (struct p2m_read_write_payload *) payload;

	tsk = find_lego_task_by_pid(hdr->src_nid, p2m_payload->pid);
	if (unlikely(!tsk)){
		/* No such process */
		retval = -ESRCH;
		goto out_reply;
	}

#ifdef DEBUG_STORAGE
	pr_info("handle_p2s_write : find task_struct : pid : %d\n", p2m_payload->pid);
#endif

	retval = m2s_write(p2m_payload, tsk);

out_reply:
	ibapi_reply_message(&retval, sizeof(retval), desc);
	return retval;
}

void m2s_test(){
	/*struct file *f;
	f = kmalloc(sizeof(struct file), GFP_KERNEL);
	f->f_mode = 0744;
	f->f_flags = O_WRONLY | O_CREAT;
	strcpy(f->f_name, "/root/yilun/test_lego_file");

	ssize_t ret;
	
	char buf[64];
	loff_t off = 0;
	strcpy(buf, "YILUN");
	pr_info("test write.\n");
	test_m2s_write(f, buf, 10, &off);
	pr_info("done test write, off value now is [%ld].\n", off);

	off = 0;
	char buf2[64];
	pr_info("test read.\n");
	test_m2s_read(f, buf2, 7, &off);
	pr_info("test read received [%s], off value now is [%ld]\n", buf2, off);
	pr_info("sleep 3min for next test\n\n\n");

	kfree(f);*/
}
