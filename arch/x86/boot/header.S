/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 * Released under the terms of the GNU GPLv2
 */

#include <asm/boot.h>
#include <asm/bootparam.h>

BOOTSEG		= 0x07c0
SYSSEG		= 0x1000

#ifndef SVGA_MODE
#define SVGA_MODE ASK_VGA
#endif

#ifndef ROOT_RDONLY
#define ROOT_RDONLY 1
#endif

	.code16
	.section ".bstext", "ax"

	.global bootsect_start
bootsect_start:
	# Normalize the start address
	ljmp	$BOOTSEG, $start2

start2:
	movw	%cs, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss
	xorw	%sp, %sp
	sti
	cld

	movw	$bugger_off_msg, %si

msg_loop:
	lodsb
	andb	%al, %al
	jz	bs_die
	movb	$0xe, %ah
	movw	$7, %bx
	int	$0x10
	jmp	msg_loop

bs_die:
	# Allow the user to press a key, then reboot
	xorw	%ax, %ax
	int	$0x16
	int	$0x19

	# int 0x19 should never return.
	# In case, invoke BIOS reset vector
	ljmp	$0xf000,$0xfff0

        .section ".bsdata", "a" 
bugger_off_msg:
	.ascii  "Use a boot loader.\r\n"
	.ascii  "\n"
	.ascii  "Remove disk and press any key to reboot...\r\n"
	.byte   0

# Kernel attributes; used by setup. (Still in the first 512-byte sector)
# This is the part 1 of the bootparam.header, from the old boot sector.

        .section ".header", "a"
        .globl  sentinel
sentinel:       .byte 0xff, 0xff        /* Used to detect broken loaders */

        .globl  hdr
hdr:
setup_sects:    .byte 0                 /* Filled in by build.c */
root_flags:     .word ROOT_RDONLY
syssize:        .long 0                 /* Filled in by build.c */
ram_size:       .word 0                 /* Obsolete */
vid_mode:       .word SVGA_MODE
root_dev:       .word 0                 /* Filled in by build.c */
boot_flag:      .word 0xAA55


	# The second sector.
        # offset 512, entry point

        .globl  _start
_start:
	# Explicitly enter this as bytes, or the assembler
	# tries to generate a 3-byte jump here, which causes
	# everything else to push off to the wrong offset.
	.byte   0xeb            # short (2-byte) jump
	.byte   start_of_setup-1f
1:

	# Part 2 of the bootparam.header
	.ascii "HdrS"


# End of part 2 header###########################################


	.section ".entrytext", "ax"
start_of_setup:
	movw	%ds, %ax
	movw	%ax, %es
	cld
