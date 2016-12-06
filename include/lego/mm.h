/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MM_H_
#define _LEGO_MM_H_

#include <asm/page.h>
#include <asm/pgtable.h>

#include <lego/pfn.h>
#include <lego/kernel.h>

#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr)	ALIGN(addr, PAGE_SIZE)

/* max_pfn_mapped:     highest direct mapped pfn over 4GB */
extern unsigned long max_pfn_mapped;

/* max_pfn:	highest pfn of this machine */
extern unsigned long max_pfn;

/*
 *  simple boot-time physical memory area allocator.
 */

extern unsigned long max_low_pfn;
extern unsigned long min_low_pfn;

/*
 * highest possible page
 */
extern unsigned long long max_possible_pfn;


#endif /* _LEGO_MM_H_ */
