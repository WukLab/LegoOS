/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_VMALLOC_H_
#define _LEGO_VMALLOC_H_

#include <lego/mm.h>
#include <lego/rbtree.h>
#include <lego/kernel.h>

#define VM_IOREMAP		0x00000001
#define VM_MAP			0x00000004	/* vmap()ed pages */
#define VM_NO_GUARD		0x00000040	/* don't add guard page */
#define VM_VPAGES		0x00000010	/* buffer for pages was vmalloc'ed */

struct vm_struct {
	struct vm_struct	*next;
	void			*addr;
	unsigned long		size;
	unsigned long		flags;
	struct page		**pages;
	unsigned int		nr_pages;
	phys_addr_t		phys_addr;
	const void		*caller;
};

struct vmap_area {
	unsigned long va_start;
	unsigned long va_end;
	unsigned long flags;
	struct rb_node rb_node;         /* address sorted rbtree */
	struct list_head list;          /* address sorted list */
	struct vm_struct *vm;
};

struct vm_struct *get_vm_area(unsigned long size, unsigned long flags);
struct vm_struct *get_vm_area_caller(unsigned long size, unsigned long flags,
				const void *caller);

struct vm_struct *__get_vm_area(unsigned long size, unsigned long flags,
				unsigned long start, unsigned long end);

struct vm_struct *__get_vm_area_caller(unsigned long size, unsigned long flags,
					unsigned long start, unsigned long end,
					const void *caller);

void free_vm_area(struct vm_struct *area);

static inline size_t get_vm_area_size(const struct vm_struct *area)
{
	/* return actual size without guard page */
	return area->size - PAGE_SIZE;
}

void *vmap(struct page **pages, unsigned int count,
	   unsigned long flags, pgprot_t prot);
void vunmap(const void *addr);

#endif /* _LEGO_VMALLOC_H_ */
