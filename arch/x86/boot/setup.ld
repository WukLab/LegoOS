/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * Linker script for the 16-bit kernel code.
 */

OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)

SECTIONS
{
	. = 0;
	.bstext		: { *(.bstext) }
	.bsdata		: { *(.bsdata) }

	. = 495;
	.header		: { *(.header) }
	.entrytext	: { *(.entrytext) }
	.inittext	: { *(.inittext) }
	.initdata	: { *(.inittext) }

	.text		: { *(.text) }
	.text32         : { *(.text32) }

	. = ALIGN(16);
	.rodata		: { *(.rodata*) }

	.videocards	: {
		video_cards = .;
		*(.videocards)
		video_cards_end = .;
	}

        . = ALIGN(16);
        .data		: { *(.data*) }

	.signature	: {
		setup_sig = .;
		LONG(0x5a5aaa55)
	}

	. = ALIGN(16);
	.bss		: {
		__bss_start = .;
		*(.bss*)
		__bss_end = .;
	}

	. = ALIGN(4096);
	.pgtable	: { *(.pgtable) }

	. = ALIGN(16);
	__end = .;

	/DISCARD/	: { *(.note*) }
	/DISCARD/	: { *(.eh_frame) }
	/DISCARD/	: { *(.comment) }

	. = ASSERT(__end <= 0x8000, "Setup too big");
}
