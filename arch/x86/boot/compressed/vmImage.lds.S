/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 */

OUTPUT_FORMAT(CONFIG_OUTPUT_FORMAT, CONFIG_OUTPUT_FORMAT, CONFIG_OUTPUT_FORMAT)

#undef i386

#include <asm/page.h>

#ifdef CONFIG_X86_64
OUTPUT_ARCH(i386:x86-64)
ENTRY(startup_64)
#else
OUTPUT_ARCH(i386)
ENTRY(startup_32)
#endif

SECTIONS
{
	/*
	 * Be careful parts of head_64.S assume startup_32 is at
	 * address 0.
	 */
	. = 0;
	.head.text : {
		_head = .;
		*(.head.text)
		_ehead = .;
	}

	. = ALIGN(PAGE_SIZE);
	.compressed_kernel : {
		_kernel = .;
		*(.compressed_kernel)
		_ekernel = .;
	}
	. = ALIGN(PAGE_SIZE);

	.text :	{
		_text = .;
		*(.text*)
		_etext = .;
	}

	.rodata : {
		_rodata = .;
		*(.rodata*)
		_erodata = .;
	}

	.data :	{
		_data = .;
		*(.data*)
		_edata = .;
	}

	. = ALIGN(64);
	.bss : {
		_bss = .;
		*(.bss*)
		_ebss = .;
	}

#ifdef CONFIG_X86_64
       . = ALIGN(PAGE_SIZE);
       .pgtable : {
		_pgtable = .;
		*(.pgtable)
		_epgtable = .;
	}
#endif
	_end = .;
}
