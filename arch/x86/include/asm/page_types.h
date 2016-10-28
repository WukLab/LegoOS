/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 */

#ifndef _ASM_X86_PAGE_TYPES_H_
#define _ASM_X86_PAGE_TYPES_H_

#include <disos/const.h>

#define PAGE_SHIFT		12
#define PAGE_SIZE		(_AC(1,UL) << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE-1))

#ifdef CONFIG_X86_64
/*
 * x86-64
 *
 * Set __PAGE_OFFSET to the most negative possible address +
 * PGDIR_SIZE*16 (pgd slot 272).  The gap is to allow a space for a
 * hypervisor to fit.  Choosing 16 slots here is arbitrary, but it's
 * what Xen requires.
 */
#define __PAGE_OFFSET		_AC(0xffff880000000000, UL)

#define __START_KERNEL_map	_AC(0xffffffff80000000, UL)

/* See Documentation/x86/x86_64/mm.txt for a description of the memory map. */
#define __PHYSICAL_MASK_SHIFT	46
#define __VIRTUAL_MASK_SHIFT	47

#else /* CONFIG_X86_64 */
/*
 * i386
 *
 * This handles the memory map.
 *
 * A __PAGE_OFFSET of 0xC0000000 means that the kernel has
 * a virtual address space of one gigabyte, which limits the
 * amount of physical memory you can use to about 950MB.
 */
#define __PAGE_OFFSET		_AC(CONFIG_PAGE_OFFSET, UL)
#define __START_KERNEL_map	__PAGE_OFFSET
#endif

#define __PHYSICAL_START	CONFIG_PHYSICAL_START

#define __START_KERNEL		(__START_KERNEL_map + __PHYSICAL_START)

#endif /* _ASM_X86_PAGE_TYPES_H_ */
