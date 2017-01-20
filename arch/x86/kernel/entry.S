/*
 * entry.S contains the system-call and fault low-level handling routines.
 *
 * A note on terminology:
 * - iret frame:	Architecture defined interrupt frame from SS to RIP
 *			at the top of the kernel process stack.
 *
 * Some macro usage:
 * - ENTRY/END:		Define functions in the symbol table.
 * - IDT_ENTRY:		Define exception entry points.
 * - INTERRUPT:		Define interrupt entry points
 */

#include <asm/ptrace.h>
#include <asm/irq_vectors.h>
#include <lego/linkage.h>

#include "entry.h"

/*
 * IDT_ENTRY - Intel Reserved Vector Handler
 * Corresponding to Intel's software developer manual, e.g. page fault.
 */
.macro IDT_ENTRY sym do_sym has_error_code:req
ENTRY(\sym)
	.ifeq \has_error_code
	pushq	$-1			/* ORIG_RAX: no syscall to restart */
	.endif

	/*
	 * Save all registers in pt_regs
	 */
	cld
	ALLOC_PT_GPREGS_ON_STACK
	SAVE_C_REGS
	SAVE_EXTRA_REGS

	movq	%rsp, %rdi		/* pt_regs pointer */

	.if \has_error_code
	movq	ORIG_RAX(%rsp), %rsi	/* get error code */
	movq	$-1, ORIG_RAX(%rsp)	/* no syscall to restart */
	.else
	xorl	%esi, %esi		/* no error code */
	.endif

	call	\do_sym

	RESTORE_EXTRA_REGS
	RESTORE_C_REGS
	REMOVE_PT_GPREGS_FROM_STACK 8
	iretq
END(\sym)
.endm

IDT_ENTRY divide_error			do_divide_error			has_error_code=0
IDT_ENTRY debug				do_debug			has_error_code=0
IDT_ENTRY nmi				do_nmi				has_error_code=0
IDT_ENTRY int3				do_int3				has_error_code=0
IDT_ENTRY overflow			do_overflow			has_error_code=0
IDT_ENTRY bounds			do_bounds			has_error_code=0
IDT_ENTRY invalid_op			do_invalid_op			has_error_code=0
IDT_ENTRY device_not_available		do_device_not_available		has_error_code=0
IDT_ENTRY double_fault			do_double_fault			has_error_code=1
IDT_ENTRY coprocessor_segment_overrun	do_coprocessor_segment_overrun	has_error_code=0
IDT_ENTRY stack_segment			do_stack_segment		has_error_code=1
IDT_ENTRY general_protection		do_general_protection		has_error_code=1
IDT_ENTRY invalid_TSS			do_invalid_TSS			has_error_code=1
IDT_ENTRY page_fault			do_page_fault			has_error_code=1
IDT_ENTRY segment_not_present		do_segment_not_present		has_error_code=1
IDT_ENTRY spurious_interrupt_bug	do_spurious_interrupt_bug	has_error_code=0
IDT_ENTRY coprocessor_error		do_coprocessor_error		has_error_code=0
IDT_ENTRY alignment_check		do_alignment_check		has_error_code=1
IDT_ENTRY machine_check			do_machine_check		has_error_code=0
IDT_ENTRY simd_exception		do_simd_exception		has_error_code=0
IDT_ENTRY virtualization_exception	do_virtualization_exception	has_error_code=0

/*
 * Interrupt entry/exit.
 * Interrupt entry points save only callee clobbered registers in fast path.
 * Entry runs with interrupts off.
 *
 * When called, 0(%rsp): ~(interrupt number)
 */
.macro INTR func
	cld
	ALLOC_PT_GPREGS_ON_STACK
	SAVE_C_REGS
	SAVE_EXTRA_REGS

	testb	$3, CS(%rsp)
	jz	1f

	/*
	 * IRQ from user mode.
	 * Switch to kernel gsbase.
	 */
	#SWAPGS

1:
	/*
	 * TODO:
	 * This is the point where we can switch to interrupt stack!
	 * Since Intel supports different stacks! e.g. NMI, Interrupt
	 *
	 * But for now Lego only the stack of the current thread
	 * No switching
	 */

	movq	%rsp, %rdi		/* pt_regs pointer */

	call	\func
.endm

/*
 * The interrupt stubs push (~vector+0x80) onto the stack
 * and then jump to common_interrupt.
 */
	.align 64
ENTRY(common_interrupt)
	/* Adjust vector to [-256, -1] range */
	addq	$-0x80, (%rsp)
	INTR	do_IRQ

ret_from_intr:
	cli
	testb	$3, CS(%rsp)
	jz	retint_kernel

	/* Interrupt came from user space */
retint_user:
	#swapgs
	jmp	restore_regs_and_iret

/* Returning to kernel space */
retint_kernel:
#ifdef CONFIG_PREEMPT
	/*
	 * Check if we need preemption
	 *
	 * Gotcha! This is where preemption happens!
	 */
#endif

/*
 * At this label, code paths which return to kernel and to user,
 * which come from interrupts/exception and from syscalls, merge.
 */
restore_regs_and_iret:
	RESTORE_EXTRA_REGS
restore_c_regs_and_iret:
	RESTORE_C_REGS
	REMOVE_PT_GPREGS_FROM_STACK 8
	iretq
END(common_interrupt)

/**
 * irq_entries_start	-	[0x20...FIRST_SYSTEM_VECTOR] handler
 *
 * IDT has 0xff vectors:
 *   [0x0...0x1f] are Intel reserved vectors.
 *   [0x20...FIRST_SYSTEM_VECTOR] handlers are the below handler array
 *   [FIRST_SYSTEM_VECTOR...0xff] are filled of special system vectors,
 *   the holes inside this small range are filled of spurious_interrupt().
 *
 * Check arch/x86/kernel/irqinit.c for the god damn details.
 *
 * Build the entry stubs with some assembler magic.
 * We pack 1 stub into every 8-byte block.
 */
	.align 8
ENTRY(irq_entries_start)
    vector=FIRST_EXTERNAL_VECTOR
    .rept (FIRST_SYSTEM_VECTOR - FIRST_EXTERNAL_VECTOR)
	/* Note: always in signed byte range */
	pushq	$(~vector+0x80)
    vector=vector+1
	jmp	common_interrupt
	.align	8
    .endr
END(irq_entries_start)

/*
 * APIC interrupts
 *
 * These are system interrupt handlers.
 * Thus, always come from kernel mode.
 * Lay between [FIRST_SYSTEM_VECTOR...0xff]
 */
.macro apicinterrupt num do_sym smp__sym
ENTRY(\smp__sym)
	pushq	$~(\num)
	INTR	\do_sym
	jmp	ret_from_intr
END(\smp__sym)
.endm

apicinterrupt REBOOT_VECTOR			reboot_interrupt		smp__reboot_interrupt
apicinterrupt LOCAL_TIMER_VECTOR		apic_timer_interrupt		smp__apic_timer_interrupt
apicinterrupt X86_PLATFORM_IPI_VECTOR		x86_platform_ipi		smp__x86_platform_ipi
apicinterrupt CALL_FUNCTION_SINGLE_VECTOR	call_function_single_interrupt	smp__call_function_single_interrupt
apicinterrupt CALL_FUNCTION_VECTOR		call_function_interrupt		smp__call_function_interrupt
apicinterrupt ERROR_APIC_VECTOR			error_interrupt			smp__error_interrupt
apicinterrupt SPURIOUS_APIC_VECTOR		spurious_interrupt		smp__spurious_interrupt
