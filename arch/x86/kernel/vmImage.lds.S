/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * vmImage.lds.S: ld script for the x86 kernel.
 */

#include <asm/page.h>
#include <lego/compiler.h>

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
		 * __init_task_data
		 *
		 * the init task, which needs to be aligned
		 * with THREAD_SIZE (16KB in 64bit)
		 */
		. = ALIGN(THREAD_SIZE);
		*(.data..init_task)

		/*
		 * __page_aligned_data
		 */
		. = ALIGN(PAGE_SIZE);
		*(.data..page_aligned)

		/*
		 * __read_mostly
		 */
		. = ALIGN(L1_CACHE_BYTES);
		*(.data..read_mostly)

		/*
		 * __cacheline_aligned
		 */
		. = ALIGN(L1_CACHE_BYTES);
		*(.data..cacheline_aligned)

		. = ALIGN(L1_CACHE_BYTES);
		*(.data)

		/*
		 * TODO:
		 * Per-CPU variable
		 * Maybe replaced if I build a REAL per-cpu!
		 */
		. = ALIGN(L1_CACHE_BYTES);
		__spercpu = .;
		*(.data..percpu)
		__epercpu = .;

		/* WARN_ONCE etc. */
		. = ALIGN(L1_CACHE_BYTES);
		*(.data..unlikely)

		. = ALIGN(L1_CACHE_BYTES);
		*(.data*)
		__edata = .;
	}

	/*
	 * init part can be freed and reused later
	 */

	__sinit = .;

	. = ALIGN(PAGE_SIZE);
	.init.text : {
		__sinittext = .;
		*(.init.text)
		__einittext = .;
	}

	. = ALIGN(L1_CACHE_BYTES);
	.init.data : {
		__sinitdata = .;
		*(.init.data)
		__einitdata = .;
	}

	. = ALIGN(L1_CACHE_BYTES);
	.init.rodata : {
		__sinitrodata = .;
		*(.init.rodata)
		__einitrodata = .;
	}

	/*
	 * Kernel parameter setup functions
	 * __setup(str, fn);
	 */
	. = ALIGN(L1_CACHE_BYTES);
	.init.setup : {
		__sinitsetup = .;
		*(.init.setup)
		__einitsetup = .;
	}

	. = ALIGN(L1_CACHE_BYTES);
	.x86_cpu_vendor.init : {
		__x86_cpu_vendor_start = .;
		*(.x86_cpu_vendor.init)
		__x86_cpu_vendor_end = .;
	}

	. = ALIGN(L1_CACHE_BYTES);
	.apicdrivers : {
		__apicdrivers = .;
		*(.apicdrivers)
		__apicdrivers_end = .;
	}

	__einit = .;

	.signature : {
		kernel_signature = .;
		LONG(0x5a5aaa55)
	}

	. = ALIGN(PAGE_SIZE);
	.bss : {
		__bss_start = .;
		*(.bss..page_aligned)
		*(.bss*)
		__bss_end = .;
	}

	/*
	 * Boot-time early brk-like allocator
	 * Use RESERVE_BRK() to reserve this area at compile time
	 * Use extend_brk() to allocate brk at run time
	 */
	. = ALIGN(PAGE_SIZE);
	.brk : {
		__brk_start = .;
		. += 64 * 1024;
		*(.brk_reservation)	/* areas brk users have reserved */
		__brk_limit = .;
	}

	. = ALIGN(PAGE_SIZE);

	__end = .;
}
