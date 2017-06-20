/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm_types.h>
#include <lego/mm.h>
#include <lego/netmacro.h>
#include <lego/slab.h>
#include "mem.h"

struct reply_status_addr {
	int status;
	unsigned long addr;
};

unsigned long allocate_phys_mem(int if_contiguous, int size)
{
	unsigned long addr;
	int order;
	
	addr = alloc_pages(GFP_KERNEL, order);

	return addr;
}

int mem_alloc(int sender, uintptr_t descriptor, unsigned long size, int gpid)
{
	unsigned long ret_vaddr;
	unsigned long local_vaddr;
	int status = REPLY_SUCCESS;
	int ret;
	struct reply_status_addr reply;

	local_vaddr = allocate_phys_mem(0, size);
	if (!local_vaddr)
		status = REPLY_ENOMEM;

reply:
	reply.status = status;
	reply.addr = local_vaddr;
	ret = reply_to_processor(&reply, sizeof(struct reply_status_addr), descriptor);

	return ret;
}

int mem_free(int sender, uintptr_t descriptor, unsigned long vaddr, int gpid)
{
	unsigned long local_vaddr;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	int status = REPLY_SUCCESS;
	int ret;

	mm = get_or_create_mm_from_gpid(gpid);

	vma = find_vma(mm, vaddr);
	if (!vma) {
		status = REPLY_EINVAL;
		goto reply;
	}

	local_vaddr = vaddr - vma->vm_start + vma->local_vm_start;

	kfree((void*)local_vaddr);

reply:
	ret = reply_to_processor(&status, sizeof(int), descriptor);

	return ret;
}

int mem_load(int sender, uintptr_t descriptor, unsigned long vaddr, int gpid)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long local_vaddr;
	int status = REPLY_SUCCESS;
	int ret;

	mm = get_or_create_mm_from_gpid(gpid);

	vma = find_vma(mm, vaddr);
	if (!vma) {
		status = REPLY_EINVAL;
		goto reply;
	}

	local_vaddr = vaddr - vma->vm_start + vma->local_vm_start;

reply:
	ret = reply_to_processor((char *)local_vaddr, PAGE_SIZE, descriptor);

	return ret;
}

int mem_store(int sender, uintptr_t descriptor, unsigned long vaddr, int gpid, void *buf)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long local_vaddr;
	int status = REPLY_SUCCESS;
	int ret;

	mm = get_or_create_mm_from_gpid(gpid);

	vma = find_vma(mm, vaddr);
	if (!vma) {
		status = REPLY_EINVAL;
		goto reply;
	}

	local_vaddr = vaddr - vma->vm_start + vma->local_vm_start;

	memcpy((void*)local_vaddr, buf, PAGE_SIZE);


reply:
	ret = reply_to_processor(&status, sizeof(int), descriptor);

}

