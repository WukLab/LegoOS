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

	.section ".head.text","ax"
	.code32
ENTRY(startup_64)
	cld
	cli
	movl	$(__BOOT_DS), %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
