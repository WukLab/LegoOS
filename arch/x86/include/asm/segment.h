/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_SEGMENT_H_
#define _ASM_X86_SEGMENT_H_

#include <lego/const.h>

/*
 * Constructor for a conventional segment GDT (or LDT) entry.
 * This is a macro so it can be used in initializers.
 */
#define GDT_ENTRY(flags, base, limit)			\
	((((base)  & _AC(0xff000000,ULL)) << (56-24)) |	\
	 (((flags) & _AC(0x0000f0ff,ULL)) << 40) |	\
	 (((limit) & _AC(0x000f0000,ULL)) << (48-16)) |	\
	 (((base)  & _AC(0x00ffffff,ULL)) << 16) |	\
	 (((limit) & _AC(0x0000ffff,ULL))))

/* Simple and small GDT entries for booting only: */
#define GDT_ENTRY_BOOT_CS	2
#define GDT_ENTRY_BOOT_DS	3
#define GDT_ENTRY_BOOT_TSS	4
#define __BOOT_CS		(GDT_ENTRY_BOOT_CS*8)
#define __BOOT_DS		(GDT_ENTRY_BOOT_DS*8)
#define __BOOT_TSS		(GDT_ENTRY_BOOT_TSS*8)

/*
 * Bottom two bits of selector give the ring
 * privilege level
 */
#define SEGMENT_RPL_MASK	0x3

/* User mode is privilege level 3: */
#define USER_RPL		0x3

/* Bit 2 is Table Indicator (TI): selects between LDT or GDT */
#define SEGMENT_TI_MASK		0x4
/* LDT segment has TI set ... */
#define SEGMENT_LDT		0x4
/* ... GDT has it cleared */
#define SEGMENT_GDT		0x0

#define GDT_ENTRY_INVALID_SEG		0

#define GDT_ENTRY_KERNEL32_CS		1
#define GDT_ENTRY_KERNEL_CS		2
#define GDT_ENTRY_KERNEL_DS		3

/*
 * We cannot use the same code segment descriptor for user and kernel mode,
 * not even in long flat mode, because of different DPL.
 *
 * GDT layout to get 64-bit SYSCALL/SYSRET support right. SYSRET hardcodes
 * selectors:
 *
 *   if returning to 32-bit userspace: cs = STAR.SYSRET_CS,
 *   if returning to 64-bit userspace: cs = STAR.SYSRET_CS+16,
 *
 * ss = STAR.SYSRET_CS+8 (in either case)
 *
 * thus USER_DS should be between 32-bit and 64-bit code selectors:
 */
#define GDT_ENTRY_DEFAULT_USER32_CS	4
#define GDT_ENTRY_DEFAULT_USER_DS	5
#define GDT_ENTRY_DEFAULT_USER_CS	6

/* Needs two entries */
#define GDT_ENTRY_TSS			8
/* Needs two entries */
#define GDT_ENTRY_LDT			10

#define GDT_ENTRY_TLS_MIN		12
#define GDT_ENTRY_TLS_MAX		14

/* Abused to load per CPU data from limit */
#define GDT_ENTRY_PER_CPU		15

/*
 * Number of entries in the GDT table:
 */
#define GDT_ENTRIES			16

/*
 * Segment selector values corresponding to the above entries:
 *
 * Note, selectors also need to have a correct RPL,
 * expressed with the +3 value for user-space selectors:
 */
#define __KERNEL32_CS			(GDT_ENTRY_KERNEL32_CS*8)
#define __KERNEL_CS			(GDT_ENTRY_KERNEL_CS*8)
#define __KERNEL_DS			(GDT_ENTRY_KERNEL_DS*8)
#define __USER32_CS			(GDT_ENTRY_DEFAULT_USER32_CS*8 + 3)
#define __USER_DS			(GDT_ENTRY_DEFAULT_USER_DS*8 + 3)
#define __USER32_DS			__USER_DS
#define __USER_CS			(GDT_ENTRY_DEFAULT_USER_CS*8 + 3)
#define __PER_CPU_SEG			(GDT_ENTRY_PER_CPU*8 + 3)

#define IDT_ENTRIES			256
#define NUM_EXCEPTION_VECTORS		32

/* Bitmask of exception vectors which push an error code on the stack: */
#define EXCEPTION_ERRCODE_MASK		0x00027d00

/*
 * early_idt_handler_array is an array of entry points referenced in the
 * early IDT.  For simplicity, it's a real array with one entry point
 * every nine bytes.  That leaves room for an optional 'push $0' if the
 * vector has no error code (two bytes), a 'push $vector_number' (two
 * bytes), and a jump to the common entry code (up to five bytes).
 */
#define EARLY_IDT_HANDLER_SIZE		9

#define GDT_SIZE			(GDT_ENTRIES*8)
#define GDT_ENTRY_TLS_ENTRIES		3
#define TLS_SIZE			(GDT_ENTRY_TLS_ENTRIES* 8)

/*
 * Save a segment register away:
 */
#define savesegment(seg, value)				\
	asm("mov %%" #seg ",%0":"=r" (value) : : "memory")

#define loadsegment(seg, value)				\
	asm("mov %0, %%" #seg"": : "r"(value) : "memory")

#ifndef __ASSEMBLY__
/* Defined in entry.S, with exception handling */
asmlinkage void native_load_gs_index(unsigned);
static inline void load_gs_index(unsigned int selector)
{
	native_load_gs_index(selector);
}
#endif

#endif /* _ASM_X86_SEGMENT_H_ */
