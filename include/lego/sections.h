/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_SECTIONS_H_
#define _LEGO_SECTIONS_H_

/*
 * References to section boudaries defined in linker script.
 * Every architecture must contain sections listed below.
 * See arch/$(ARCH)/kernel/vmImage.ld.S for details.
 */

extern char __text[];	/* including head bootstrap code */
extern char __stext[], __etext[];
extern char __srodata[], __erodata[];
extern char __sdata[], __edata[];
extern char __sinittext[], __einittext[];
extern char __sinitdata[], __einitdata[];
extern char __bss_start[], __bss_end[];
extern char __brk_start[], __brk_limit[];
extern char __end[];
extern char __per_cpu_load[], __per_cpu_start[], __per_cpu_end[];

static inline int init_kernel_text(unsigned long addr)
{
	if (addr >= (unsigned long)__sinittext &&
	    addr < (unsigned long)__einittext)
		return 1;
	return 0;
}

static inline int core_kernel_text(unsigned long addr)
{
	if (addr >= (unsigned long)__stext &&
	    addr < (unsigned long)__etext)
		return 1;
	return 0;
}

static inline int __kernel_text_address(unsigned long addr)
{
	if (core_kernel_text(addr))
		return 1;

	/*
	 * There might be init symbols in saved stacktraces.
	 * Give those symbols a chance to be printed in backtraces:
	 */
	if (init_kernel_text(addr))
		return 1;
	return 0;
}

#endif /* _LEGO_SECTIONS_H_ */
