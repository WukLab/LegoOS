/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This is the entry point of 16-bit setup kernel. It will do the necessary
 * sanitary checking and initilization, then jumps to main() of setup.
 *
 * To fit with GRUB2+linux+x86 boot protocol, we have to have these stuff here.
 * With this promise, we can install DisOS image into /boot/ and add an entry
 * to GRUB2 config file, then GRUB2 can boot DisOS just like booting a linux.
 * Besides, GRUB2 can pass command line parameters, initrd ptr and so on to us.
 */

#include <asm/boot.h>
#include <asm/bootparam.h>

BOOTSEG		= 0x07c0	# bootsect segment
SYSSEG		= 0x1000	# system segment (obsolete)

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
# Part 1 of the bootparam.header, from the old boot sector.

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

#
# The second sector.
# offset 512, entry point
#

        .globl  _start
_start:
	# Explicitly enter this as bytes, or the assembler
	# tries to generate a 3-byte jump here, which causes
	# everything else to push off to the wrong offset.
	.byte   0xeb            # short (2-byte) jump
	.byte   start_of_setup-1f
1:

	# Part 2 of the bootparam.header
	.ascii "HdrS"				# header signature
	.word	0x020d				# header version number


# End of part 2 header ###########################################

# Assume we are loaded by GRUB2. The related code how grub will load
# DisOS is in [grub-core/loader/i386/pc/linux.c] of grub source code tree.
#
# Normally,
#	gs = fs = es = ds = ss = Segment
#	cs = Segment + 0x20
#	ip = 0
#
# where Segment is a safe value chosed by GRUB2, which is not necessary be
# the historical 0x9000.

	.section ".entrytext", "ax"
start_of_setup:
	movw	%ds, %ax
	movw	%ax, %es
	cld

	pushw   %ds
	pushw   $1f
	lretw

1:
	calll	main

setup_bad_signature:
        movw    $setup_msg_sig, %si
setup_print:
        lodsb
        andb    %al, %al
        jz      setup_die
        movb    $0xe, %ah
        movw    $7, %bx
        int     $0x10
        jmp     setup_print

setup_die:
	# Allow the user to press a key, then reboot
	xorw	%ax, %ax
	int	$0x16
	int	$0x19

	# int 0x19 should never return.
	# In case, invoke BIOS reset vector
	ljmp	$0xf000,$0xfff0

        .section ".entrydata", "a"
setup_msg_sig:
        .ascii "No setup signature found\r\n"
	.ascii "\n"
	.ascii "Press any key to reboot...\r\n"
        .byte 0
