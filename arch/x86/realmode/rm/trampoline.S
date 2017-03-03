/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/linkage.h>
#include <asm/page.h>
#include <asm/segment.h>
#include <asm/processor-flags.h>

	.code16

	.section ".text","ax"
ENTRY(_start)
	cli

	# Normalize
	mov	%cs, %ax
	mov	%ax, %ds
	mov	%ax, %es
	mov	%ax, %ss

	# Setup stack
	movl	$rm_stack_end, %esp

	# Load idt with 0,0
	lidtl	tr_idt_desc
	lgdtl	tr_gdt_desc

	movw	$__KERNEL_DS, %dx	# Data segment descriptor

	# Enable protected mode
	movl	$X86_CR0_PE, %eax	# protected mode (PE) bit
	movl	%eax, %cr0		# into protected mode

1:
	hlt
	jmp 1b

	.code32
	.section ".text32","ax"
	.balign 4
ENTRY(startup_32)

	.code64
	.section ".text64","ax"
	.balign 4
ENTRY(startup_64)

	.section ".rodata","a"
	# Duplicate the global descriptor table
	# so the kernel can live anywhere
	.balign	16
tr_gdt_desc:
	.short	tr_gdt_end - tr_gdt	# gdt limit
	.long	tr_gdt

	.balign 16
tr_gdt:
	.quad	0x00cf9b000000ffff	# __KERNEL32_CS
	.quad	0x00af9b000000ffff	# __KERNEL_CS
	.quad	0x00cf93000000ffff	# __KERNEL_DS
tr_gdt_end:

	.balign	16
tr_idt_desc: .fill 1, 6, 0		# IDT 0,0

	.section ".data"
	.balign	16
HEAP:
	.long	rm_heap
heap_end:
	.long	rm_stack

	.section ".bss"
	.balign	16
rm_heap:
	.space	2048
rm_stack:
	.space	2048
rm_stack_end:
