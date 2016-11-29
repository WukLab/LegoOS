/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_PAGE_TYPES_H_
#define _ASM_X86_PAGE_TYPES_H_

#include <lego/const.h>
#include <lego/types.h>

#define PAGE_SHIFT		12
#define PAGE_SIZE		(_AC(1,UL) << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE-1))

#define PMD_PAGE_SIZE		(_AC(1, UL) << PMD_SHIFT)
#define PMD_PAGE_MASK		(~(PMD_PAGE_SIZE-1))

#define PUD_PAGE_SIZE		(_AC(1, UL) << PUD_SHIFT)
#define PUD_PAGE_MASK		(~(PUD_PAGE_SIZE-1))

#define __PHYSICAL_MASK		((phys_addr_t)((1ULL << __PHYSICAL_MASK_SHIFT) - 1))
#define __VIRTUAL_MASK		((1UL << __VIRTUAL_MASK_SHIFT) - 1)

/* Cast *PAGE_MASK to a signed type so that it is sign-extended if
   virtual addresses are 32-bits but physical addresses are larger
   (ie, 32-bit PAE). */
#define PHYSICAL_PAGE_MASK	(((signed long)PAGE_MASK) & __PHYSICAL_MASK)
#define PHYSICAL_PMD_PAGE_MASK	(((signed long)PMD_PAGE_MASK) & __PHYSICAL_MASK)
#define PHYSICAL_PUD_PAGE_MASK	(((signed long)PUD_PAGE_MASK) & __PHYSICAL_MASK)

#define THREAD_SIZE_ORDER	2
#define THREAD_SIZE		(PAGE_SIZE << THREAD_SIZE_ORDER)
#define CURRENT_MASK		(~(THREAD_SIZE - 1))

#define EXCEPTION_STACK_ORDER	(0)
#define EXCEPTION_STKSZ		(PAGE_SIZE << EXCEPTION_STACK_ORDER)

#define DEBUG_STACK_ORDER	(EXCEPTION_STACK_ORDER + 1)
#define DEBUG_STKSZ		(PAGE_SIZE << DEBUG_STACK_ORDER)

#define IRQ_STACK_ORDER		(2)
#define IRQ_STACK_SIZE		(PAGE_SIZE << IRQ_STACK_ORDER)

#define DOUBLEFAULT_STACK	1
#define NMI_STACK		2
#define DEBUG_STACK		3
#define MCE_STACK		4
#define N_EXCEPTION_STACKS	4  /* hw limit: 7 */

/*
 * Set __PAGE_OFFSET to the most negative possible address +
 * PGDIR_SIZE*16 (pgd slot 272).  The gap is to allow a space for a
 * hypervisor to fit.  Choosing 16 slots here is arbitrary, but it's
 * what Xen requires.
 */
#define __PAGE_OFFSET		_AC(0xffff880000000000, UL)
#define __START_KERNEL_map	_AC(0xffffffff80000000, UL)

/* See Documentation/x86/x86_64/mm.txt for description */
#define MAX_PHYSADDR_BITS	44
#define MAX_PHYSMEM_BITS	46
#define MAXMEM			_AC(__AC(1, UL) << MAX_PHYSMEM_BITS, UL)
#define __PHYSICAL_MASK_SHIFT	46
#define __VIRTUAL_MASK_SHIFT	47

#define __PHYSICAL_START	CONFIG_PHYSICAL_START

#define __START_KERNEL		(__START_KERNEL_map + __PHYSICAL_START)

#define __va(x)	((void *)((unsigned long)(x) + __START_KERNEL_map))
#define __pa(x)	((unsigned long)((unsigned long)x - __START_KERNEL_map))

#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)
#define START_KERNEL		((unsigned long)__START_KERNEL)

#endif /* _ASM_X86_PAGE_TYPES_H_ */
