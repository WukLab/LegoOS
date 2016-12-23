/*
 * entry.S contains the system-call and fault low-level handling routines.
 *
 * Some of this is documented in Documentation/x86/entry_64.txt
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
#include <asm/irq_vectors.h>
#include <lego/linkage.h>

/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
#define R15		0*8
#define R14		1*8
#define R13		2*8
#define R12		3*8
#define RBP		4*8
#define RBX		5*8
/* These regs are callee-clobbered. Always saved on kernel entry. */
#define R11		6*8
#define R10		7*8
#define R9		8*8
#define R8		9*8
#define RAX		10*8
#define RCX		11*8
#define RDX		12*8
#define RSI		13*8
#define RDI		14*8
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
#define ORIG_RAX	15*8

/* Return frame for iretq */
#define RIP		16*8
#define CS		17*8
#define EFLAGS		18*8
#define RSP		19*8
#define SS		20*8

#define SIZEOF_PTREGS	21*8

.macro ALLOC_PT_GPREGS_ON_STACK addskip=0
	addq	$-(15*8+\addskip), %rsp
.endm

.macro SAVE_C_REGS_HELPER offset=0 rax=1 rcx=1 r8910=1 r11=1
	.if \r11
	movq	%r11, 6*8+\offset(%rsp)
	.endif

	.if \r8910
	movq	%r10, 7*8+\offset(%rsp)
	movq	%r9,  8*8+\offset(%rsp)
	movq	%r8,  9*8+\offset(%rsp)
	.endif

	.if \rax
	movq	%rax, 10*8+\offset(%rsp)
	.endif

	.if \rcx
	movq	%rcx, 11*8+\offset(%rsp)
	.endif

	movq	%rdx, 12*8+\offset(%rsp)
	movq	%rsi, 13*8+\offset(%rsp)
	movq	%rdi, 14*8+\offset(%rsp)
.endm

.macro SAVE_C_REGS offset=0
	SAVE_C_REGS_HELPER \offset, 1, 1, 1, 1
.endm

.macro SAVE_C_REGS_EXCEPT_RAX_RCX offset=0
	SAVE_C_REGS_HELPER \offset, 0, 0, 1, 1
.endm

.macro SAVE_C_REGS_EXCEPT_R891011
	SAVE_C_REGS_HELPER 0, 1, 1, 0, 0
.endm

.macro SAVE_C_REGS_EXCEPT_RCX_R891011
	SAVE_C_REGS_HELPER 0, 1, 0, 0, 0
.endm

.macro SAVE_C_REGS_EXCEPT_RAX_RCX_R11
	SAVE_C_REGS_HELPER 0, 0, 0, 1, 0
.endm

.macro SAVE_EXTRA_REGS offset=0
	movq	%r15, 0*8+\offset(%rsp)
	movq	%r14, 1*8+\offset(%rsp)
	movq	%r13, 2*8+\offset(%rsp)
	movq	%r12, 3*8+\offset(%rsp)
	movq	%rbp, 4*8+\offset(%rsp)
	movq	%rbx, 5*8+\offset(%rsp)
.endm

.macro RESTORE_EXTRA_REGS offset=0
	movq 0*8+\offset(%rsp), %r15
	movq 1*8+\offset(%rsp), %r14
	movq 2*8+\offset(%rsp), %r13
	movq 3*8+\offset(%rsp), %r12
	movq 4*8+\offset(%rsp), %rbp
	movq 5*8+\offset(%rsp), %rbx
.endm

.macro ZERO_EXTRA_REGS
	xorl	%r15d, %r15d
	xorl	%r14d, %r14d
	xorl	%r13d, %r13d
	xorl	%r12d, %r12d
	xorl	%ebp, %ebp
	xorl	%ebx, %ebx
.endm

.macro RESTORE_C_REGS_HELPER rstor_rax=1, rstor_rcx=1, rstor_r11=1, rstor_r8910=1, rstor_rdx=1
	.if \rstor_r11
	movq 6*8(%rsp), %r11
	.endif

	.if \rstor_r8910
	movq 7*8(%rsp), %r10
	movq 8*8(%rsp), %r9
	movq 9*8(%rsp), %r8
	.endif

	.if \rstor_rax
	movq 10*8(%rsp), %rax
	.endif

	.if \rstor_rcx
	movq 11*8(%rsp), %rcx
	.endif

	.if \rstor_rdx
	movq 12*8(%rsp), %rdx
	.endif

	movq 13*8(%rsp), %rsi
	movq 14*8(%rsp), %rdi
.endm

.macro RESTORE_C_REGS
	RESTORE_C_REGS_HELPER 1,1,1,1,1
.endm

.macro RESTORE_C_REGS_EXCEPT_RAX
	RESTORE_C_REGS_HELPER 0,1,1,1,1
.endm

.macro RESTORE_C_REGS_EXCEPT_RCX
	RESTORE_C_REGS_HELPER 1,0,1,1,1
.endm

.macro RESTORE_C_REGS_EXCEPT_R11
	RESTORE_C_REGS_HELPER 1,1,0,1,1
.endm

.macro RESTORE_C_REGS_EXCEPT_RCX_R11
	RESTORE_C_REGS_HELPER 1,0,0,1,1
.endm

.macro REMOVE_PT_GPREGS_FROM_STACK addskip=0
	subq $-(15*8+\addskip), %rsp
.endm

/*
 * Interrupt entry/exit.
 *
 * Interrupt entry points save only callee clobbered registers in fast path.
 *
 * Entry runs with interrupts off.
 */
/* 0(%rsp): ~(interrupt number) */
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
	 * This is the point where we can switch to
	 * interrupt stack!
	 * But now Lego only has one type of stack.
	 */

	/* rdi points to pt_regs */
	call	\func
.endm

.macro IDT_ENTRY sym do_sym has_error_code:req
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
 * The interrupt stubs push (~vector+0x80) onto the stack
 * and then jump to common_interrupt.
 */
	.align 64
ENTRY(common_interrupt)
	/* Adjust vector to [-256, -1] range */
	addq	$-0x80, (%rsp)
	INTR	do_IRQ

ret_from_intr:
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
 * irq_entries_start	-	[0x20...FIRST_SYSTEM_VECTOR handler
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
 * APIC interrupts.
 */
.macro apicinterrupt num do_sym __sym
ENTRY(\__sym)
	pushq	$~(\num)
	INTR	\do_sym
	jmp	ret_from_intr
END(\__sym)
.endm

apicinterrupt REBOOT_VECTOR			reboot_interrupt		__reboot_interrupt
apicinterrupt LOCAL_TIMER_VECTOR		apic_timer_interrupt		__apic_timer_interrupt
apicinterrupt X86_PLATFORM_IPI_VECTOR		x86_platform_ipi		__x86_platform_ipi
apicinterrupt CALL_FUNCTION_SINGLE_VECTOR	call_function_single_interrupt	__call_function_single_interrupt
apicinterrupt CALL_FUNCTION_VECTOR		call_function_interrupt		__call_function_interrupt
apicinterrupt ERROR_APIC_VECTOR			error_interrupt			__error_interrupt
apicinterrupt SPURIOUS_APIC_VECTOR		spurious_interrupt		__spurious_interrupt
