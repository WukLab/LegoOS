/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/kernel.h>
#include <lego/comp_memory.h>
#include <lego/comp_storage.h>
#include <memory/include/vm.h>
#include <memory/include/file_ops.h>
#include <lego/fit_ibapi.h>

extern char __ramfs_start[], __ramfs_end[];

static ssize_t ramfs_read(struct lego_task_struct *tsk, struct lego_file *file,
			  char *buf, size_t count, loff_t *pos)
{
	char *start;

	start = __ramfs_start + *pos;
	memcpy(buf, start, count);
	*pos += count;

	return count;
}

static ssize_t ramfs_write(struct lego_task_struct *tsk, struct lego_file *file,
			   const char *buf, size_t count, loff_t *pos)
{
	return -EINVAL;
}

static int ramfs_vma_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
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

	ramfs_read(tsk, file, (char *)page, count, &pos);

	vmf->page = page;

	return 0;
}

static struct vm_operations_struct ramfs_vma_ops = {
	.fault	= ramfs_vma_fault,
};

static int ramfs_mmap(struct lego_task_struct *tsk, struct lego_file *file,
		      struct vm_area_struct *vma)
{
	vma->vm_ops = &ramfs_vma_ops;
	return 0;
}

struct lego_file_operations ramfs_file_ops = {
	.read	= ramfs_read,
	.write	= ramfs_write,
	.mmap	= ramfs_mmap,
};

static ssize_t storage_read(struct lego_task_struct *tsk, struct lego_file *file,
			char *buf, size_t count, loff_t *pos)
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
	if (unlikely(!msg)) {
		return -ENOMEM;
	}

	opcode = (__u32 *) msg;
	payload = (struct m2s_read_write_payload *) (msg + sizeof(__u32));

	*opcode = M2S_READ;

	payload->uid = current_uid();
	strcpy(payload->filename, file->filename);
	payload->flags = O_RDONLY;
	payload->len = count;
	payload->offset = *pos;

	/* retbuf = retval + content*/
	len_ret = sizeof(retval) + count;
	retbuf = kmalloc(len_ret, GFP_KERNEL);

	if(unlikely(!retbuf)){
		return -ENOMEM;
	}

	ibapi_send_reply_imm(STORAGE_NODE, msg, len_msg, retbuf, len_ret, false);

	retval_in_buf = (ssize_t *) retbuf;
	content = (char *) (retbuf + sizeof(ssize_t));

	retval = *retval_in_buf;
	/* now copy content to __user buf */
	memcpy(buf, content, count);

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
	//pr_info("storage_vma_fault : called.\n");
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

	//pr_info("mmaped page_fault for filename [%s]\n", file->filename);

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
