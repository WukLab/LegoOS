/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/slab.h>
#include <lego/files.h>
#include <lego/kernel.h>
#include <lego/uaccess.h>
#include <lego/fit_ibapi.h>
#include <lego/comp_storage.h>

#include <memory/task.h>
#include <memory/pid.h>
#include <memory/vm.h>
#include <memory/file_types.h>

#ifdef CONFIG_DEBUG_M2S_READ_WRITE
#define m2s_debug(fmt, ...)					\
	pr_debug("%s() cpu%d "fmt"\n",				\
		__func__, smp_processor_id(), __VA_ARGS__)
#else
static inline void m2s_debug(const char *fmt, ...) { }
#endif

ssize_t __storage_read(struct lego_task_struct *tsk, char *f_name,
		       char __user *buf, size_t count, loff_t *pos)
{
	u32 len_msg, len_ret, *opcode;
	void *msg, *retbuf, *content;
	ssize_t retval, *retval_ptr;
	struct m2s_read_write_payload *payload;

	len_msg = sizeof(*opcode) + sizeof(*payload);
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	/* retbuf = retval + content */
	len_ret = sizeof(retval) + count;
	retbuf = kmalloc(len_ret, GFP_KERNEL);
	if(!retbuf) {
		kfree(msg);
		return -ENOMEM;
	}

	opcode = msg;
	*opcode = M2S_READ;

	payload = msg + sizeof(*opcode);
	payload->uid = current_uid();
	payload->flags = O_RDONLY;
	payload->len = count;
	payload->offset = *pos;
	strncpy(payload->filename, f_name, MAX_FILENAME_LENGTH);

	m2s_debug("f_name:[%s] len:%#lx offset:%#Lx",
		payload->filename, payload->len, payload->offset);

	ibapi_send_reply_imm(STORAGE_NODE, msg, len_msg, retbuf, len_ret, false);

	/* The first 8 bytes are the nr of bytes been read */
	retval_ptr = retbuf;
	retval = *retval_ptr;

	m2s_debug("2 retval: %zu", retval);

	/* The left is the content itself */
	content = retbuf + sizeof(*retval_ptr);

	/*
	 * buf can point to a kernel virtual address or user
	 * virual address. lego_copy_to_user will take care.
	 */
	lego_copy_to_user(tsk, buf, content, count);

	kfree(msg);
	kfree(retbuf);
	return retval;
}

ssize_t storage_read(struct lego_task_struct *tsk,
		     struct lego_file *file,
		     char *buf, size_t count, loff_t *pos)
{
	BUG_ON(!file->filename);
	return __storage_read(tsk, file->filename, buf, count, pos);
}

/*
 * perform m2s write
 * @tsk: unused
 * @f_name: filename to write to
 * @count: nrbytes of write
 * @pos: offset where nrbytes write start
 * return value: nrbytes no success, -errno on fail
 */
ssize_t __storage_write(struct lego_task_struct *tsk, char *f_name,
			const char *buf, size_t count, loff_t *pos)
{
	u32 len_msg, *opcode;
	void *msg, *content;
	ssize_t retval;
	struct m2s_read_write_payload *payload;
	int retlen;

	/* msg = opcode + payload + send_buffer */
	len_msg = sizeof(*opcode) + sizeof(*payload) + count;
	msg = kmalloc(len_msg, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	opcode = msg;
	*opcode = M2S_WRITE;

	payload = msg + sizeof(*opcode);
	payload->uid = current_uid();
	payload->flags = O_WRONLY;
	payload->len = count;
	payload->offset = *pos;
	strncpy(payload->filename, f_name, MAX_FILENAME_LENGTH);

	content = msg + sizeof(*opcode) + sizeof(*payload);

	//lego_copy_from_user(tsk, content, buf, count);
	memcpy(content, buf, count);

	m2s_debug("f_name:[%s] len:%#lx offset:%#Lx",
		payload->filename, payload->len, payload->offset);

	retlen = ibapi_send_reply_imm(STORAGE_NODE, msg, len_msg,
				&retval, sizeof(retval), false);

	if (unlikely(retlen != sizeof(retval)))
		retval = -EIO;

	m2s_debug("2 retval: %zu", retval);

	kfree(msg);
	return retval;

}

static ssize_t storage_write(struct lego_task_struct *tsk, struct lego_file *file,
		const char *buf, size_t count, loff_t *pos)
{
	BUG_ON(!file->filename);
	return __storage_write(tsk, file->filename, buf, count, pos);
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
	pos = vmf->pgoff << PAGE_SHIFT;
	count = PAGE_SIZE;

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
