/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_SETUP_H_
#define _ASM_X86_SETUP_H_

#define SECONDARY_STARTUP_64_ALIGN 0x200

/*
 * The setup.h is used by both 16-bit setup kernel image
 * and the setup.c in 64-bit kernel.
 */

#define COMMAND_LINE_SIZE	2048

#define OLD_CL_MAGIC		0xA33F
#define OLD_CL_ADDRESS		0x020	/* Relative to real mode data */
#define NEW_CL_POINTER		0x228	/* Relative to real mode data */

#ifndef __ASSEMBLY__

#include <asm/bootparam.h>
#include <lego/linkage.h>
#include <lego/compiler.h>

extern struct boot_params boot_params;

void __init setup_arch(void);
void __init early_setup_arch(void);
asmlinkage __visible void __init x86_64_start_kernel(char *real_mode_data);

/* exceedingly early brk-like allocator */
extern unsigned long _brk_end;
void *extend_brk(size_t size, size_t align);

/*
 * Reserve space in the brk section.  The name must be unique within
 * the file, and somewhat descriptive.  The size is in bytes.  Must be
 * used at file scope.
 *
 * (This uses a temp function to wrap the asm so we can pass it the
 * size parameter; otherwise we wouldn't be able to.  We can't use a
 * "section" attribute on a normal variable because it always ends up
 * being @progbits, which ends up allocating space in the vmlinux
 * executable.)
 */
#define RESERVE_BRK(name,sz)						\
	static void __used						\
	__brk_reservation_fn_##name##__(void) {				\
		asm volatile (						\
			".pushsection .brk_reservation,\"aw\",@nobits;" \
			".brk." #name ":"				\
			" 1:.skip %c0;"					\
			" .size .brk." #name ", . - 1b;"		\
			" .popsection"					\
			: : "i" (sz));					\
	}

void  __init early_alloc_pgt_buf(void);

extern unsigned long initial_code;
extern unsigned long initial_stack;
extern unsigned long initial_gs;

#endif /* __ASSEMBLY */

#endif /* _ASM_X86_SETUP_H_ */
