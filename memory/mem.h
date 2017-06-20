/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <net/arch/cc.h>

#define TASK_SIZE   ((1UL << 47) - PAGE_SIZE)

#define TASK_UNMAPPED_BASE      (PAGE_ALIGN(TASK_SIZE / 3))

/*
 * Top of mmap area (just below the process stack).
 *
 * Leave an at least ~128 MB hole with possible stack randomization.
 */
#define MIN_GAP (128*1024*1024UL)
#define MAX_GAP (TASK_SIZE/6*5)

/*
 * Limit the stack by to some sane default: 
 * 128MB seems reasonable.
 */
#define _STK_LIM        (128*1024*1024)

/*
 * vm_flags in vm_area_struct, see mm_types.h.
 */
#define VM_NONE         0x00000000

#define VM_READ         0x00000001      /* currently active flags */
#define VM_WRITE        0x00000002
#define VM_EXEC         0x00000004
#define VM_SHARED       0x00000008

#define VM_CAN_NONLINEAR 0x08000000	/* Has ->fault & does nonlinear pages */
#define VM_MIXEDMAP	0x10000000	/* Can contain "struct page" and pure PFN pages */
#define VM_SAO		0x20000000	/* Strong Access Ordering (powerpc) */
#define VM_PFN_AT_MMAP	0x40000000	/* PFNMAP vma that is fully mapped at mmap time */
#define VM_MERGEABLE	0x80000000	/* KSM may merge identical pages */

unsigned long allocate_phys_mem(int if_contiguous, int size);

struct vm_area_struct* find_vma(struct mm_struct *mm, unsigned long addr);

struct mm_struct* get_or_create_mm_from_gpid(int gpid);

int reply_to_processor(char *buf, int size, uintptr_t descriptor);

int mem_mmap(int sender, uintptr_t descriptor, unsigned long size, char* filename, unsigned long offset, int flag, int gpid);
int mem_munmap(int sender, uintptr_t descriptor, unsigned long vaddr, int gpid);
int mem_msync(int sender, uintptr_t descriptor, unsigned long vaddr, unsigned long size, int gpid);

int mem_alloc(int sender, uintptr_t descriptor, unsigned long size, int gpid);
int mem_free(int sender, uintptr_t descriptor, unsigned long vaddr, int gpid);
int mem_load(int sender, uintptr_t descriptor, unsigned long vaddr, int gpid);
int mem_store(int sender, uintptr_t descriptor, unsigned long vaddr, int gpid, void *buf);
