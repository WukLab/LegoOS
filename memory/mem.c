/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/net.h>
#include <lego/netmacro.h>
#include <lego/list.h>
#include <lego/slab.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/fit_ibapi.h>
#include "mem.h"

LIST_HEAD(mm_list);

int reply_to_processor(char *buf, int size, uintptr_t descriptor)
{
	int ret;

	ret = ibapi_reply_message(buf, size, descriptor);

	return ret;
}

struct mem_op_header {
	int op;
	int gpid;
};

int lego_handle_receive_message(int sender, void *msg, uint32_t msgsize, uintptr_t descriptor)
{
	struct mem_op_header *header = (struct mem_op_header *)msg;
	char *data = (char *)msg + sizeof(struct mem_op_header);
	int size, flag;
	unsigned long vaddr, offset;
	char *filename;

	switch(header->op) {
		case OP_ALLOC:
			size = *((int*)data);
			mem_alloc(sender, descriptor, size, header->gpid);
			break;
		case OP_FREE:
			vaddr = *((unsigned long*)data);
			mem_free(sender, descriptor, vaddr, header->gpid);
			break;
		case OP_MMAP:
			size = *((int*)data);
			flag = *((int *)(data+sizeof(int)));
			offset = *((unsigned long *)(data+2*sizeof(int)));
			filename = data+2*sizeof(int)+sizeof(unsigned long);
			mem_mmap(sender, descriptor, size, filename, offset, flag, header->gpid);
			break;
		case OP_MUNMAP:
			vaddr = *((unsigned long*)data);
			mem_munmap(sender, descriptor, vaddr, header->gpid);
			break;
		case OP_MSYNC:
			size = *((int*)data);
			vaddr = *((unsigned long*)(data+sizeof(int)));
			mem_msync(sender, descriptor, vaddr, size, header->gpid);
			break;
		case OP_LOAD:
			vaddr = *((unsigned long*)data);
			mem_load(sender, descriptor, vaddr, header->gpid);
			break;
		case OP_STORE:
			vaddr = *((unsigned long*)data);
			mem_store(sender, descriptor, vaddr, header->gpid, data+sizeof(unsigned long));
			break;
		default:
			break;
	}

	return 0;
}

static unsigned long mmap_base(void)
{
	unsigned long gap = _STK_LIM;

	if (gap < MIN_GAP)
		gap = MIN_GAP;
	else if (gap > MAX_GAP)
		gap = MAX_GAP;

	return PAGE_ALIGN(TASK_SIZE - gap);
}

struct mm_struct* get_or_create_mm_from_gpid(int gpid)
{
	struct mm_struct *entry, *mm = NULL;

	list_for_each_entry(entry, &mm_list, list) {
		if (gpid == entry->gpid) {
			return entry;
		}
	}

	mm = (struct mm_struct *)kzalloc(sizeof(struct mm_struct), GFP_KERNEL);
	BUG_ON(!mm);

	list_add(&mm->list, &mm_list);

	mm->mmap_base = mmap_base();

	return mm;
}

void mem_handle_fault(struct task_struct *task, unsigned long address)
{
	struct vm_area_struct *vma;
	char *filename;
	unsigned long file_offset;
	int size;
	int gpid;
	char *buf;
	int ret;

	/* getting faulting user processor info */
	vma = find_vma(current->mm, address); 
	filename = vma->vm_file;
	file_offset = vma->vm_pgoff << PAGE_SHIFT;
	size = PAGE_SIZE;
	gpid = vma->vm_mm->gpid;

	/* allocating physical page */
	// buf = 

	/* get data from storage */
	//ret = read_from_storage(filename, file_offset, PAGE_SIZE, gpid, buf);

	return;
}

void memcomponent_init(void)
{
	ibapi_reg_send_reply_rdma_imm_handler(lego_handle_receive_message);
}

void memory_cleanup(void)
{
}
