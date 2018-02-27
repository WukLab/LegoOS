/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Trampoline code used to boot secondary CPUs.
 * Invoked by BSP by sending APIC INIT to this CPU.
 *
 * This file actually is a combination of:
 *	arch/x86/boot/pmjump.S:			(16bit->32bit transition)
 *	arch/x86/boot/compressed/head_64.S:	(32bit->64bit transition)
 *
 * At last it will jump to [arch/x86/kernel/head_64.S] to enter kernel.
 */

#include <lego/linkage.h>
#include <asm/msr.h>
#include <asm/page.h>
#include <asm/setup.h>
#include <asm/segment.h>
#include <asm/processor-flags.h>

#define NR_PGTABLE 6

	.section ".text","ax"
	.code16
ENTRY(_start)
	cli
	wbinvd

	xorl	%eax, %eax
	mov	%cs, %ax
	mov	%ax, %ds
	mov	%ax, %es
	mov	%ax, %ss

	# PA already changed by previous CPU?
	movl	pa_changed, %ebx
	testl	%ebx, %ebx
	jnz	1f

	# No, we are the FIRST secondary cpu
	shll	$4, %eax
	addl	%eax, pa_tr_gdt
	addl	%eax, 2f
	movl	$1, pa_changed

1:
	# Setup stack
	movl	$rm_stack_end, %esp

	# Load idt with 0,0
	lidtl	tr_idt_desc
	lgdtl	tr_gdt_desc

	xorl	%edx, %edx
	movw	$__KERNEL_DS, %dx	# Data segment descriptor

	# Enable protected mode
	movl	$X86_CR0_PE, %eax	# protected mode (PE) bit
	movl	%eax, %cr0		# into protected mode

	# Transition to 32-bit mode
	.byte	0x66, 0xea		# ljmpl opcode
2:	.long	startup_32		# offset
	.word	__KERNEL32_CS		# segment

	.section ".text32","ax"
	.code32
	.balign 4
ENTRY(startup_32)
	movl	%edx, %ss
	movl	%edx, %ds
	movl	%edx, %es
	movl	%edx, %fs
	movl	%edx, %gs

	# Get the address where we are loaded
	call	1f
1:	popl	%ebp
	subl	$1b, %ebp

	# Setup mini stack
	leal	rm_stack_end(%ebp), %esp

	# Enable PAE mode
	movl	%cr4, %eax
	orl     $X86_CR4_PAE, %eax
	movl    %eax, %cr4

	/*
	 * Build early 4GB boot pagetable
	 * Identity mapping, using 2MB page size.
	 *
	 * Level 4: entry 0
	 * Level 3: entry 0~3
	 * Level 2: entry 0~511, need 4 full level-2 pgtables
	 */

	/* Clear pagetables */
	leal	pgtable(%ebp), %edi
	xorl	%eax, %eax
	movl	$((NR_PGTABLE * 4096) / 4), %ecx
	rep
	stosl

	/* Build Level 4 */
	leal	pgtable + 0(%ebp), %edi
	leal	0x1007(%edi), %eax
	movl	%eax, 0(%edi)

	/* Build Level 3 */
	leal	pgtable + 0x1000(%ebp), %edi
	leal	0x1007(%edi), %eax
	movl	$4, %ecx
1:	movl	%eax, 0x00(%edi)
	addl	$0x00001000, %eax
	addl	$8, %edi
	decl	%ecx
	jnz	1b

	/* Build Level 2 */
	leal	pgtable + 0x2000(%ebp), %edi
	movl	$0x00000183, %eax
	movl	$2048, %ecx
1:	movl	%eax, 0(%edi)
	addl	$0x00200000, %eax
	addl	$8, %edi
	decl	%ecx
	jnz	1b

	/* Enable the boot page tables */
	leal	pgtable(%ebp), %eax
	movl	%eax, %cr3

	/*
	 * Set IA32_EFER.LME = 1
	 * Enable Long mode in EFER (Extended Feature Enable Register)
	 */
	movl	$MSR_EFER, %ecx
	rdmsr
	btsl	$_EFER_LME, %eax
	wrmsr

	# Enable paging and in turn activate Long Mode
	movl	$(X86_CR0_PG | X86_CR0_WP | X86_CR0_PE), %eax
	movl	%eax, %cr0

	/*
	 * Setup for the jump to 64bit mode
	 *
	 * When the jump is performend we will be in long mode but
	 * in 32bit compatibility mode with EFER.LME = 1, CS.L = 0, CS.D = 1
	 * (and in turn EFER.LMA = 1).	To jump into 64bit mode we use
	 * the new gdt/idt that has __KERNEL_CS with CS.L = 1.
	 * We place all of the values on our mini stack so lret can
	 * used to perform that far jump.
	 */
	pushl	$__KERNEL_CS
	leal	startup_64(%ebp), %eax
	pushl	%eax

	# Transition to 64-bit mode
	lret

	.code64
	.section ".text64","ax"
	.balign 4
ENTRY(startup_64)
	cld

	/* Setup data segments. */
	xorl	%eax, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
	movl	%eax, %fs
	movl	%eax, %gs

	/*
	 * Jump to kernel
	 * arch/x86/kernel/head_64.S
	 */
	movq	$(CONFIG_PHYSICAL_START + SECONDARY_STARTUP_64_ALIGN), %rax
	jmpq	*%rax

# DATA Section
	.data
	# Duplicate the global descriptor table
	# so the kernel can live anywhere
	.balign	16
tr_gdt_desc:
	.short	tr_gdt_end - tr_gdt	# gdt limit
pa_tr_gdt:
	.long	tr_gdt			# gdt address

	.balign 16
tr_gdt:
	.quad	0
	.quad	0x00cf9b000000ffff	# __KERNEL32_CS
	.quad	0x00af9b000000ffff	# __KERNEL_CS
	.quad	0x00cf93000000ffff	# __KERNEL_DS
tr_gdt_end:

	.balign	16
tr_idt_desc: .fill 1, 6, 0		# IDT 0,0

	.balign 8
pa_changed:
	.long	0

# BSS Section
	.bss
	.balign	16
rm_stack:
	.space	128
rm_stack_end:

	.align PAGE_SIZE
pgtable:
	.space NR_PGTABLE * PAGE_SIZE
