/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * Linker script for the 16-bit kernel code.
 */

OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)

SECTIONS
{
	. = 0;
	.bstext :	{ *(.bstext) }
	.bsdata :	{ *(.bsdata) }

	. = 495;
	.header :	{ *(.header) }
	.entrytext :	{ *(.entrytext) }

	/DISCARD/ :	{ *(.note*) }
	/DISCARD/ :	{ *(.eh_frame) }
	/DISCARD/ :	{ *(.comment) }
}
