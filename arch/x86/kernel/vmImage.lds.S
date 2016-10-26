/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * ld script for the x86 kernel.
 */

/* in case the preprocessor is a 32bit one */
#undef i386

OUTPUT_FORMAT(CONFIG_OUTPUT_FORMAT, CONFIG_OUTPUT_FORMAT, CONFIG_OUTPUT_FORMAT)

#ifdef CONFIG_X86_64
#define LOAD_OFFSET	__PAGE_OFFSET
OUTPUT_ARCH(i386:x86-64)
ENTRY(startup_64)
#else
#define LOAD_OFFSET	__START_KERNEL_map
OUTPUT_ARCH(i386)
ENTRY(startup_32)
#endif

SECTIONS {

	. = CONFIG_PHYSICAL_START;

	.text : {
		_text = .;

		*(.head.text)
		. = ALIGN(8);

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
