/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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

	_end = .;
}
