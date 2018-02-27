/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/page.h>

#undef i386

OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)

SECTIONS
{
	. = 0;
	.text :	{
		*(.text)
	}

	. = ALIGN(64);
	.text32 : {
		*(.text32*)
	}

	. = ALIGN(64);
	.text64 : {
		*(.text64*)
	}

	. = ALIGN(64);
	.rodata : {
		*(.rodata*)
	}

	. = ALIGN(64);
	.data :	{
		*(.data*)
	}

	.signature : {
		trampoline_signature = .;
		LONG(0x5a5aaa55)
	}

	. = ALIGN(64);
	.bss : {
		_bss = .;
		*(.bss*)
		_ebss = .;
	}
}
