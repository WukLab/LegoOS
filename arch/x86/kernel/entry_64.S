/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/ptrace.h>

#include <lego/linkage.h>

.macro idt_entry sym do_sym has_error_code:req
ENTRY(\sym)
	.ifeq \has_error_code
	pushq	$-1			/* ORIG_RAX: no syscall to restart */
	.endif
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
