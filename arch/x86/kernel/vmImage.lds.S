/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * vmImage.lds.S: ld script for the x86 kernel.
 */

#include <asm/page.h>
#include <asm/setup.h>
#include <asm/percpu.h>
#include <lego/compiler.h>
#include <lego/vmImage.lds.h>

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

#define PT_LOAD	1
PHDRS {
	text PT_LOAD FLAGS(5);          /* R_E */
	data PT_LOAD FLAGS(6);          /* RW_ */
	percpu PT_LOAD FLAGS(6);        /* RW_ */
	init PT_LOAD FLAGS(7);          /* RWE */
}

SECTIONS {
	. = LOAD_OFFSET + CONFIG_PHYSICAL_START;

#ifdef CONFIG_X86_64
	phys_startup_64 = ABSOLUTE(startup_64 - LOAD_OFFSET);
#else
	phys_startup_32 = ABSOLUTE(startup_32 - LOAD_OFFSET);
#endif

	.text : AT(ADDR(.text) - LOAD_OFFSET) {
		__text = .;

		/* Bootstrapping code */
		*(.head.text)
		. = ALIGN(L1_CACHE_BYTES);

		/* Whole story */
		__stext = .;
		*(.text*)
		SCHED_TEXT
		FIXUP_TEXT
		/* End of text section */
		__etext = .;
	} :text = 0x9090

	EXCEPTION_TABLE(16) :text = 0x9090

	. = ALIGN(PAGE_SIZE);
	.rodata : AT(ADDR(.rodata) - LOAD_OFFSET) {
		__srodata = .;
		*(.rodata*)
		__erodata = .;
	}

	. = ALIGN(PAGE_SIZE);
	.data : AT(ADDR(.data) - LOAD_OFFSET) {
		__sdata = .;

		/*
		 * the init task, which needs to be aligned
		 * with THREAD_SIZE (16KB in 64bit)
		 */
		. = ALIGN(THREAD_SIZE);
		*(.data..init_task)

		. = ALIGN(PAGE_SIZE);
		*(.data..page_aligned)

		. = ALIGN(L1_CACHE_BYTES);
		*(.data..read_mostly)

		. = ALIGN(L1_CACHE_BYTES);
		*(.data..cacheline_aligned)

		/* Normal data */
		. = ALIGN(L1_CACHE_BYTES);
		*(.data)

		/* variables inside WARN_ONCE etc. */
		. = ALIGN(L1_CACHE_BYTES);
		*(.data..unlikely)

		__edata = .;
	} :data

	/* Init code and data - will be freed after init */
	. = ALIGN(PAGE_SIZE);
	.init.begin : AT(ADDR(.init.begin) - LOAD_OFFSET) {
		__sinit = .;
	}

	/*
	 * percpu offsets are zero-based on SMP.  PERCPU_VADDR() changes the
	 * output PHDR, so the next output section - .init.text - should
	 * start another segment - init.
	 */
	PERCPU_VADDR(L1_CACHE_BYTES, 0, :percpu)
	ASSERT(SIZEOF(.data..percpu) < CONFIG_PHYSICAL_START,
		"per-CPU data too large - increase CONFIG_PHYSICAL_START")

	. = ALIGN(PAGE_SIZE);
	.init.text : AT(ADDR(.init.text) - LOAD_OFFSET) {
		__sinittext = .;
		*(.init.text)
		__einittext = .;
	} :init

	. = ALIGN(L1_CACHE_BYTES);
	.init.data : AT(ADDR(.init.data) - LOAD_OFFSET) {
		__sinitdata = .;
		*(.init.data)
		__einitdata = .;
	}

	. = ALIGN(L1_CACHE_BYTES);
	.init.rodata : AT(ADDR(.init.rodata) - LOAD_OFFSET) {
		__sinitrodata = .;
		*(.init.rodata)
		__einitrodata = .;
	}

	/*
	 * Kernel parameter setup functions
	 * __setup(str, fn);
	 */
	. = ALIGN(L1_CACHE_BYTES);
	.init.setup : AT(ADDR(.init.setup) - LOAD_OFFSET) {
		__sinitsetup = .;
		*(.init.setup)
		__einitsetup = .;
	}

	. = ALIGN(L1_CACHE_BYTES);
	.init.trampoline : AT(ADDR(.init.trampoline) - LOAD_OFFSET) {
		__sinittrampoline = .;
		*(.init.trampoline)
		__einittrampoline = .;
	}

	. = ALIGN(L1_CACHE_BYTES);
	.x86_cpu_vendor.init : AT(ADDR(.x86_cpu_vendor.init) - LOAD_OFFSET) {
		__x86_cpu_vendor_start = .;
		*(.x86_cpu_vendor.init)
		__x86_cpu_vendor_end = .;
	}

	. = ALIGN(L1_CACHE_BYTES);
	.profile.point : AT(ADDR(.profile.point) - LOAD_OFFSET) {
		__sprofilepoint = .;
		*(.profile.point)
		__eprofilepoint = .;
	}

	/*
	 * struct alt_inst entries. From the header (alternative.h):
	 * "Alternative instructions for different CPU types or capabilities"
	 * Think locking instructions on spinlocks.
	 */
	. = ALIGN(L1_CACHE_BYTES);
	.altinstructions : AT(ADDR(.altinstructions) - LOAD_OFFSET) {
		__alt_instructions = .;
		*(.altinstructions)
		__alt_instructions_end = .;
	}

	/*
	 * And here are the replacement instructions. The linker sticks
	 * them as binary blobs. The .altinstructions has enough data to
	 * get the address and the length of them to patch the kernel safely.
	 */
	.altinstr_replacement : AT(ADDR(.altinstr_replacement) - LOAD_OFFSET) {
		__alt_replacement = .;
		*(.altinstr_replacement)
		__alt_replacement_end = .;
	}

	. = ALIGN(L1_CACHE_BYTES);
	.apicdrivers : AT(ADDR(.apicdrivers) - LOAD_OFFSET) {
		__apicdrivers = .;
		*(.apicdrivers)
		__apicdrivers_end = .;
	}

/* XXX: remove me later */
#ifdef CONFIG_COMP_MEMORY
	. = ALIGN(PAGE_SIZE);
	.ramfs : AT(ADDR(.ramfs) - LOAD_OFFSET) {
		__ramfs_start = .;
		*(.ramfs)
		__ramfs_end = .;
	}
#endif

	__einit = .;

	/* Checked during boot-time */
	.signature : AT(ADDR(.signature) - LOAD_OFFSET) {
		kernel_signature = .;
		LONG(0x5a5aaa55)
	}

	/* Real-content ends here */

	/* BSS */
	. = ALIGN(PAGE_SIZE);
	.bss : AT(ADDR(.bss) - LOAD_OFFSET) {
		__bss_start = .;
		*(.bss..page_aligned)
		*(.bss*)
		. = ALIGN(PAGE_SIZE);
		__bss_end = .;
	}

	/*
	 * Boot-time early brk-like allocator
	 * Use RESERVE_BRK() to reserve this area at compile time
	 * Use extend_brk() to allocate brk at run time
	 */
	. = ALIGN(PAGE_SIZE);
	.brk : AT(ADDR(.brk) - LOAD_OFFSET) {
		__brk_start = .;
		. += 64 * 1024;
		*(.brk_reservation)	/* areas brk users have reserved */
		__brk_limit = .;
	}

	. = ALIGN(PAGE_SIZE);
	__end = .;
}

/*
 * Per-cpu symbols which need to be offset from __per_cpu_load
 * for the boot processor.
 *
 * Used by head.S
 */
#define INIT_PER_CPU(x)		\
	INIT_PER_CPU_VAR(x) = x + __per_cpu_load

INIT_PER_CPU(per_cpu_head_start);
INIT_PER_CPU(cpu_gdt_page);
