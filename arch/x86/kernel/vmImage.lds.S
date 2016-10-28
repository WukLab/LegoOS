/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * ld script for the x86 kernel.
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

SECTIONS {
	. = LOAD_OFFSET + CONFIG_PHYSICAL_START;

#ifdef CONFIG_X86_64
	phys_startup_64 = ABSOLUTE(startup_64 - LOAD_OFFSET);
#else
	phys_startup_32 = ABSOLUTE(startup_32 - LOAD_OFFSET);
#endif

	.text : {
		_text = .;

		/* Bootstrapping code */
		*(.head.text)
		. = ALIGN(8);

		/* Whole story */
		_stext = .;
		*(.text*)
		_etext = .;
	}

	.rodata : {
		_srodata = .;
		*(.rodata*)
		_erodata = .;
	}

	.data : {
		_sdata = .;
		*(.data*)
		_edata = .;
	}

	.bss : {
		__bss_start = .;
		*(.bss*)
		__bss_end = .;
	}

	_end = .;
}
