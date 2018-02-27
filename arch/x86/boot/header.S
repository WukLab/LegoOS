/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This is the entry point of 16-bit setup kernel. It will do the necessary
 * sanitary checking and initilization, then jumps to main() of setup.
 *
 * To fit with GRUB2+linux+x86 boot protocol, we have to have these stuff here.
 * With this promise, we can install LegoOS image into /boot/ and add an entry
 * to GRUB2 config file, then GRUB2 can boot LegoOS just like booting a linux.
 * Besides, GRUB2 can pass command line parameters, initrd ptr and so on to us.
 */

#include "boot.h"

#include <asm/boot.h>
#include <asm/setup.h>
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

/*
 * Kernel attributes; used by setup. (Still in the first 512-byte sector)
 * Part 1 of the bootparam.header, from the old boot sector.
 */

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

/*
 * The second sector.
 * offset 512, entry point
 */

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
		.word	0x020a				# header version number

		.globl realmode_swtch
realmode_swtch:	.word	0, 0		# default_switch, SETUPSEG
start_sys_seg:	.word	SYSSEG		# obsolete and meaningless, but just
					# in case something decided to "use" it
		.word	kernel_version-512 # pointing to kernel version string
					# above section of header is compatible
					# with loadlin-1.5 (header v1.5). Don't
					# change it.

type_of_loader:	.byte	0		# 0 means ancient bootloader, newer
					# bootloaders know to change this.
					# See Documentation/x86/boot.txt for
					# assigned ids

# flags, unused bits must be zero (RFU) bit within loadflags
loadflags:
		.byte	LOADED_HIGH	# The kernel is to be loaded high

setup_move_size: .word  0x8000		# size to move, when setup is not
					# loaded at 0x90000. We will move setup
					# to 0x90000 then just before jumping
					# into the kernel. However, only the
					# loader knows how much data behind
					# us also needs to be loaded.

code32_start:				# here loaders can put a different
					# start address for 32-bit code.
		.long	0x100000	# 0x100000 = default for big kernel

ramdisk_image:	.long	0		# address of loaded ramdisk image
					# Here the loader puts the 32-bit
					# address where it loaded the image.
					# This only will be read by the kernel.

ramdisk_size:	.long	0		# its size in bytes

bootsect_kludge:
		.long	0		# obsolete

heap_end_ptr:	.word	__end+STACK_SIZE-512
					# (Header version 0x0201 or later)
					# space from here (exclusive) down to
					# end of setup code can be used by setup
					# for local heap purposes.

ext_loader_ver:
		.byte	0		# Extended boot loader version
ext_loader_type:
		.byte	0		# Extended boot loader type

cmd_line_ptr:	.long	0		# (Header version 0x0202 or later)
					# If nonzero, a 32-bit pointer
					# to the kernel command line.
					# The command line should be
					# located between the start of
					# setup and the end of low
					# memory (0xa0000), or it may
					# get overwritten before it
					# gets read.  If this field is
					# used, there is no longer
					# anything magical about the
					# 0x90000 segment; the setup
					# can be located anywhere in
					# low memory 0x10000 or higher.

initrd_addr_max: .long 0x7fffffff
					# (Header version 0x0203 or later)
					# The highest safe address for
					# the contents of an initrd
					# The current kernel allows up to 4 GB,
					# but leave it at 2 GB to avoid
					# possible bootloader bugs.

kernel_alignment:  .long CONFIG_PHYSICAL_ALIGN	#physical addr alignment
						#required for protected mode
						#kernel
relocatable_kernel:     .byte 0
#define MIN_KERNEL_ALIGN_LG2	21
min_alignment:		.byte MIN_KERNEL_ALIGN_LG2	# minimum alignment

xloadflags:
#ifdef CONFIG_X86_64
# define XLF0 1		/* 64-bit kernel */
#else
# define XLF0 0
#endif
			.word XLF0

cmdline_size:   .long   COMMAND_LINE_SIZE-1     #length of the command line,
                                                #added with boot protocol
                                                #version 2.06

hardware_subarch:	.long 0			# subarchitecture, added with 2.07
						# default to 0 for normal x86 PC

hardware_subarch_data:	.quad 0

#define ZO_input_data		0
#define ZO_z_input_len		0
payload_offset:		.long ZO_input_data
payload_length:		.long ZO_z_input_len

setup_data:		.quad 0			# 64-bit physical pointer to
						# single linked list of
						# struct setup_data

pref_address:		.quad 0x100000		# preferred load addr

#define VO__text 0
#define VO__end  1
#define INIT_SIZE (VO__end - VO__text)
init_size:		.long INIT_SIZE		# kernel initialization size
handover_offset:	.long 0			# Filled in by build.c

# End of part 2 header ###########################################

/*
 * Assume we are loaded by GRUB2. The related code how grub will load
 * LegoOS is in [grub-core/loader/i386/pc/linux.c] of grub source code tree.
 *
 * Normally,
 *	gs = fs = es = ds = ss = Segment
 *	cs = Segment + 0x20
 *	ip = 0
 *
 * where Segment is a safe value chosed by GRUB2, which is not necessary be
 * the historical 0x9000.
 */

	.section ".entrytext", "ax"
start_of_setup:
	movw	%ds, %ax
	movw	%ax, %es
	cld

	movw	%ss, %dx
	cmpw	%ax, %dx	# %ds == %ss?
	movw	%sp, %dx
	je	2f		# -> assume %sp is reasonably set

	# Invalid %ss, make up a new stack
	movw	$__end, %dx
	testb	$CAN_USE_HEAP, loadflags
	jz	1f
	movw	heap_end_ptr, %dx
1:
	addw	$STACK_SIZE, %dx
	jnc	2f
	xorw	%dx, %dx	# Avoid wraparound

2:
	# Now %dx should point to the end of our stack space
	andw	$~3, %dx	# dword align (might as well...)
	jnz	3f
	movw	$0xfffc, %dx	# Make sure we're not zero
3:
	movw	%ax, %ss	# %ss = %ds = %es for sure
	movzwl	%dx, %esp	# Clear upper half of %esp
	sti			# Now we should have a working stack

# We will have entered with %cs = %ds+0x20, normalize %cs so
# it is on par with the other segments.
	pushw   %ds
	pushw   $1f
	lretw

1:
	# Check the signature of the setup image
	cmpl	$0x5a5aaa55, setup_sig
	jne	setup_bad_signature

	# zero the bss
	movw	$__bss_start, %di
	movw	$__end+3, %cx
	xorl	%eax, %eax
	subw    %di, %cx
	shrw    $2, %cx
	rep; stosl

	# Jump to C code, should never return
	calll	main

setup_bad_signature:
        movw    $setup_msg_sig, %si
setup_print:
        lodsb
        andb    %al, %al
        jz      die
        movb    $0xe, %ah
        movw    $7, %bx
        int     $0x10
        jmp     setup_print

	.globl	die
	.type	die, @function
die:
	hlt
	jmp	die

	.size	die, .-die

        .section ".entrydata", "a"
setup_msg_sig:
        .ascii "No setup signature found\r\n"
	.ascii "\n"
	.ascii "Press any key to reboot...\r\n"
        .byte 0
