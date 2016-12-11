/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_TLBFLUSH_H_
#define _ASM_X86_TLBFLUSH_H_

static inline void __flush_tlb_single(unsigned long addr)
{
	asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
}

static inline void __flush_tlb_one(unsigned long addr)
{
	__flush_tlb_single(addr);
}

static inline void __flush_tlb_all(void)
{
	write_cr3(read_cr3());
}

#endif /* _ASM_X86_TLBFLUSH_H_ */
