/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This is the head of our kernel, also the entry point of our kernel.
 * It is loaded at 0x100000 by bootloader, and jumped from real-mode
 * setup kernel. We alreay in 32-bit protected mode, and will transit
 * to long mode as soon as possible.
 */

#include <asm/segment.h>
#include <disos/linkage.h>
#include <disos/compiler.h>

	.text

	.section ".head.text","ax"
	.code32
ENTRY(startup_32)
	cld
	cli
	movl	$(__BOOT_DS), %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss

	/* setup our own stack */
	movl	$boot_stack_end, %esp

	call	1f
1:
	popl	%ebp
	subl	$1b, %ebp

	.code64
	.org 0x200
ENTRY(startup_64)
	xorl	%eax, %eax

	.section ".data"
gdt:
	.word	gdt_end - gdt
	.long	gdt
	.word	0
	.quad	0x0000000000000000	/* NULL descriptor */
	.quad	0x00af9a000000ffff	/* __KERNEL_CS */
	.quad	0x00cf92000000ffff	/* __KERNEL_DS */
	.quad	0x0080890000000000	/* TS descriptor */
	.quad   0x0000000000000000	/* TS continued */
gdt_end:

/* Temporary stack and heap */
	.bss
	.balign 4
boot_heap:
	.fill 0x8000, 1, 0
boot_stack:
	.fill 0x4000, 1, 0
boot_stack_end:

/* Page tables */
	.section ".pgtable","a",@nobits
	.balign 4096
pgtable:
	.fill 6*4096, 1, 0
