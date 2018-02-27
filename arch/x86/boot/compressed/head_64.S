/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * Note that:
 *	%esi points to the bootparam structure.
 */

#include <asm/msr.h>
#include <asm/boot.h>
#include <asm/segment.h>
#include <asm/processor-flags.h>
#include <lego/linkage.h>

#define NR_PGTABLE 6

	.text
	.code32
	.section ".head.text","ax"
GLOBAL(startup_32)
	cld
	cli

	/*
	 * Get the address where we are loaded
	 * well, it is 0x100000 that we are talking about.
	 */
	call	1f
1:	popl	%ebp
	subl	$1b, %ebp

	/* Setup a mini stack */
	movl	$boot_stack_end, %eax
	addl	%ebp, %eax
	movl	%eax, %esp

	/*
	 * Load new GDT with the 64bit segments using 32bit descriptor.
	 * These descriptors has .L = 1, indicates that these segments
	 * contains native 64-bit code.
	 */
	leal	gdt(%ebp), %eax
	movl	%eax, gdt+2(%ebp)
	lgdt	gdt(%ebp)

	/*
	 * Enable PAE mode
	 * Note: If CR0.PG = 0, paging is not used. In this case,
	 * CR4.PAE and IA32_EFER.LME are ignored by the processor.
	 */
	movl	%cr4, %eax
	orl	$X86_CR4_PAE, %eax
	movl	%eax, %cr4

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

	/* After gdt is loaded */
	xorl	%eax, %eax
	lldt	%ax
	movl    $__BOOT_TSS, %eax
	ltr	%ax

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

	/* Enter paged protected Mode, activating Long Mode */
	movl	$(X86_CR0_PG | X86_CR0_PE), %eax
	movl	%eax, %cr0

	/* Jump from 32bit compatibility mode into 64bit mode. */
	lret
ENDPROC(startup_32)

	.code64
	.org 0x200
ENTRY(startup_64)
	/* Setup data segments. */
	xorl	%eax, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
	movl	%eax, %fs
	movl	%eax, %gs

	/* Save real-mode bootparam ptr */
	pushq	%rsi

	/* Copy kernel to CONFIG_PHYSICAL_START */
	movq	$_ekernel, %rcx
	subq	$_kernel, %rcx
	shrq	$3, %rcx
	incq	%rcx
	leaq	_kernel(%rbp), %rsi
	movq	$CONFIG_PHYSICAL_START, %rdi
	rep
	movsq

	/* Restore real-mode bootparam ptr */
	popq	%rsi

	/*
	 * Jump to kernel
	 * arch/x86/kernel/head_64.S
	 */
	movq	$CONFIG_PHYSICAL_START, %rax
	jmpq	*%rax

	.data
gdt:
	.word	gdt_end - gdt
	.long	gdt
	.word	0			/* 			0	*/
	.quad	0x0000000000000000	/* NULL descriptor	1	*/
	.quad	0x00af9a000000ffff	/* __KERNEL_CS		2	*/
	.quad	0x00cf92000000ffff	/* __KERNEL_DS		3	*/
	.quad	0x0080890000000000	/* TS descriptor	4	*/
	.quad   0x0000000000000000	/* TS continued		5	*/
gdt_end:

	.bss
	.balign 4
boot_heap:
	.fill 0x1000, 1, 0
boot_stack:
	.fill 0x1000, 1, 0
boot_stack_end:

	.section ".pgtable","a",@nobits
	.balign 4096
pgtable:
	.fill NR_PGTABLE * 4096, 1, 0
