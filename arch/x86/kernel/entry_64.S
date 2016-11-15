/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * x86-64 ABI:
 * ---------------------------------------------------------------------------
 * arguments           |  callee-saved      | extra caller-saved | return
 * [callee-clobbered]   |                    | [callee-clobbered] |
 * ---------------------------------------------------------------------------
 * rdi rsi rdx rcx r8-9 | rbx rbp [*] r12-15 | r10-11             | rax, rdx [**]
 *
 * ( rsp is obviously invariant across normal function calls. (gcc can 'merge'
 * functions when it sees tail-call optimization possibilities) rflags is
 * clobbered. Leftover arguments are passed over the stack frame.)
 *
 * [*]  In the frame-pointers case rbp is fixed to the stack frame.
 *
 * [**] For struct return values wider than 64 bits the return convention is a
 *	bit more complex: up to 128 bits width we return small structures
 *	straight in rax, rdx. For structures larger than that (3 words or
 *	larger) the caller puts a pointer to an on-stack return struct
 *	[allocated in the caller's stack frame] into the first argument - i.e.
 *	into rdi. All other arguments shift up by one in this case.
 *	Fortunately this case is rare in the kernel.
 */

#include <asm/ptrace.h>

#include <lego/linkage.h>

.macro idt_entry sym do_sym has_error_code:req
ENTRY(\sym)
	.ifeq \has_error_code
	pushq	$-1			/* ORIG_RAX: no syscall to restart */
	.endif

	/* Save all */
	pushq	%rdi
	pushq	%rsi
	pushq	%rdx
	pushq	%rcx
	pushq	%rax
	pushq	%r8
	pushq	%r9
	pushq	%r10
	pushq	%r11
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15

	movq	%rsp, %rdi		/* pt_regs pointer */

	.if \has_error_code
	movq	ORIG_RAX(%rsp), %rsi	/* get error code */
	movq	$-1, ORIG_RAX(%rsp)	/* no syscall to restart */
	.else
	xorl	%esi, %esi		/* no error code */
	.endif

	call	\do_sym

	/* Restore all */
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	popq	%r11
	popq	%r10
	popq	%r9
	popq	%r8
	popq	%rax
	popq	%rcx
	popq	%rdx
	popq	%rsi
	popq	%rdi
	addq	$8, %rsp		/* orig_ax */

	iretq
END(\sym)
.endm

idt_entry divide_error			do_divide_error			has_error_code=0
idt_entry debug				do_debug			has_error_code=0
idt_entry nmi				do_nmi				has_error_code=0
idt_entry int3				do_int3				has_error_code=0
idt_entry overflow			do_overflow			has_error_code=0
idt_entry bounds			do_bounds			has_error_code=0
idt_entry invalid_op			do_invalid_op			has_error_code=0
idt_entry device_not_available		do_device_not_available		has_error_code=0
idt_entry double_fault			do_double_fault			has_error_code=1
idt_entry coprocessor_segment_overrun	do_coprocessor_segment_overrun	has_error_code=0
idt_entry stack_segment			do_stack_segment		has_error_code=1
idt_entry general_protection		do_general_protection		has_error_code=1
idt_entry invalid_TSS			do_invalid_TSS			has_error_code=1
idt_entry page_fault			do_page_fault			has_error_code=1
idt_entry segment_not_present		do_segment_not_present		has_error_code=1
idt_entry spurious_interrupt_bug	do_spurious_interrupt_bug	has_error_code=0
idt_entry coprocessor_error		do_coprocessor_error		has_error_code=0
idt_entry alignment_check		do_alignment_check		has_error_code=1
idt_entry machine_check			do_machine_check		has_error_code=0
idt_entry simd_exception		do_simd_exception		has_error_code=0
idt_entry virtualization_exception	do_virtualization_exception	has_error_code=0
