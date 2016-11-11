/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * vmImage.lds.S: ld script for the x86 kernel.
 */

#include <asm/page.h>

/* in case the preprocessor is a 32bit one */
#undef i386

OUTPUT_FORMAT(CONFIG_OUTPUT_FORMAT, CONFIG_OUTPUT_FORMAT, CONFIG_OUTPUT_FORMAT)

#ifdef CONFIG_X86_64
ENTRY(startup_64)
OUTPUT_ARCH(i386:x86-64)
# define LOAD_OFFSET	__START_KERNEL_map
#else
ENTRY(startup_32)
OUTPUT_ARCH(i386)
# define LOAD_OFFSET	__PAGE_OFFSET
#endif

#define L1_CACHE_BYTES 64

SECTIONS {
	. = LOAD_OFFSET + CONFIG_PHYSICAL_START;

#ifdef CONFIG_X86_64
	phys_startup_64 = ABSOLUTE(startup_64 - LOAD_OFFSET);
#else
	phys_startup_32 = ABSOLUTE(startup_32 - LOAD_OFFSET);
#endif

	.text : {
		__text = .;

		/* Bootstrapping code */
		*(.head.text)
		. = ALIGN(8);

		/* Whole story */
		__stext = .;
		*(.text*)
		__etext = .;
	}

	. = ALIGN(PAGE_SIZE);
	.rodata : {
		__srodata = .;
		*(.rodata*)
		__erodata = .;
	}

	. = ALIGN(PAGE_SIZE);
	.data : {
		__sdata = .;

		/*
		 * the init task, which needs to be aligned
		 * with THREAD_SIZE (16KB in 64bit)
		 */
		. = ALIGN(THREAD_SIZE);
		*(.data..init_task)

		/* __read_mostly */
		. = ALIGN(L1_CACHE_BYTES);
		*(.data..read_mostly)
		. = ALIGN(L1_CACHE_BYTES);

		. = ALIGN(L1_CACHE_BYTES);
		*(.data)
		. = ALIGN(L1_CACHE_BYTES);

		/* WARN_ONCE etc. */
		. = ALIGN(L1_CACHE_BYTES);
		*(.data..unlikely)
		. = ALIGN(L1_CACHE_BYTES);

		*(.data*)
		__edata = .;
	}

	. = ALIGN(PAGE_SIZE);
	.init.text : {
		__sinittext = .;
		*(.init.text)
		__einittext = .;
	}

	. = ALIGN(16);
	.init.data : {
		__sinitdata = .;
		*(.init.data)
		__einitdata = .;
	}

	.signature : {
		kernel_signature = .;
		LONG(0x5a5aaa55)
	}

	. = ALIGN(PAGE_SIZE);
	.bss : {
		__bss_start = .;
		*(.bss*)
		__bss_end = .;
	}

	__end = .;
}
