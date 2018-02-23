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

#include <asm/asm.h>
#include <asm/page.h>
#include <asm/ptrace.h>
#include <asm/percpu.h>
#include <asm/segment.h>
#include <asm/extable.h>
#include <asm/alternative-asm.h>
#include <asm/irq_vectors.h>
#include <asm/thread_info.h>
#include <asm/processor-flags.h>
#include <asm/processor-features-flags.h>

#include <lego/errno.h>
#include <lego/linkage.h>
#include <generated/asm-offsets.h>

#include "abi.h"

ENTRY(ignore_sysret)
	mov	$-ENOSYS, %eax
	sysret
END(ignore_sysret)

#define SWAPGS	swapgs

/*
 * 64-bit SYSCALL instruction entry. Up to 6 arguments in registers.
 *
 * This is the only entry point used for 64-bit system calls.  The
 * hardware interface is reasonably well designed and the register to
 * argument mapping Linux uses fits well with the registers that are
 * available when SYSCALL is used.
 *
 * SYSCALL instructions can be found inlined in libc implementations as
 * well as some other programs and libraries.  There are also a handful
 * of SYSCALL instructions in the vDSO used, for example, as a
 * clock_gettimeofday fallback.
 *
 * 64-bit SYSCALL saves rip to rcx, clears rflags.RF, then saves rflags to r11,
 * then loads new ss, cs, and rip from previously programmed MSRs.
 * rflags gets masked by a value from another MSR (so CLD and CLAC
 * are not needed). SYSCALL does not save anything on the stack
 * and does not change rsp.
 *
 * Registers on entry:
 * rax  system call number
 * rcx  return address
 * r11  saved rflags (note: r11 is callee-clobbered register in C ABI)
 * rdi  arg0
 * rsi  arg1
 * rdx  arg2
 * r10  arg3 (needs to be moved to rcx to conform to C ABI)
 * r8   arg4
 * r9   arg5
 * (note: r12-r15, rbp, rbx are callee-preserved in C ABI)
 *
 * Only called from user space.
 *
 * When user can change pt_regs->foo always force IRET. That is because
 * it deals with uncanonical addresses better. SYSRET has trouble
 * with them due to bugs in both AMD and Intel CPUs.
 */

/* Interrupts are off on entry */
ENTRY(entry_SYSCALL_64)
	SWAPGS

	/*
	 * SYSCALL does not change rsp for us!
	 * Save the previous rsp and load the top of kernel stack.
	 * It must be the top of kernel stack, since we came here
	 * from *userspace*.
	 */
	movq	%rsp, PER_CPU_VAR(rsp_scratch)
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp

	/*
	 * Construct struct pt_regs on stack
	 *
	 * In any syscall handler, you can use
	 *	current_pt_regs()
	 * to get these registers.
	 */
	pushq	$__USER_DS			/* pt_regs->ss */
	pushq	PER_CPU_VAR(rsp_scratch)	/* pt_regs->sp */
	pushq	%r11				/* pt_regs->flags */
	pushq	$__USER_CS			/* pt_regs->cs */
	pushq	%rcx				/* pt_regs->ip */
	pushq	%rax				/* pt_regs->orig_ax */
	pushq	%rdi				/* pt_regs->di */
	pushq	%rsi				/* pt_regs->si */
	pushq	%rdx				/* pt_regs->dx */
	pushq	%rcx				/* pt_regs->cx */
	pushq	$-ENOSYS			/* pt_regs->ax */
	pushq	%r8				/* pt_regs->r8 */
	pushq	%r9				/* pt_regs->r9 */
	pushq	%r10				/* pt_regs->r10 */
	pushq	%r11				/* pt_regs->r11 */
	sub	$(6*8), %rsp			/* pt_regs->bp, bx, r12-15 */

/*
 * TODO:
 * Lego uses the SYSCALL slowpath compared with Linux
 * This may have performance issues.
 */

entry_SYSCALL64_slow_path:
	/* IRQs are off. */
	SAVE_EXTRA_REGS

	movq	%rsp, %rdi
	call	do_syscall_64			/* return with IRQs disabled */

return_from_SYSCALL_64:
	RESTORE_EXTRA_REGS

	/*
	 * Try to use SYSRET instead of IRET if we're returning to
	 * a completely clean 64-bit userspace context.
	 */
	movq	RCX(%rsp), %rcx
	movq	RIP(%rsp), %r11
	cmpq	%rcx, %r11			/* RCX == RIP */
	jne	opportunistic_sysret_failed

	/*
	 * On Intel CPUs, SYSRET with non-canonical RCX/RIP will #GP
	 * in kernel space.  This essentially lets the user take over
	 * the kernel, since userspace controls RSP.
	 *
	 * If width of "canonical tail" ever becomes variable, this will need
	 * to be updated to remain correct on both old and new CPUs.
	 */
	.ifne __VIRTUAL_MASK_SHIFT - 47
	.error "virtual address width changed -- SYSRET checks need update"
	.endif

	/* Change top 16 bits to be the sign-extension of 47th bit */
	shl	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
	sar	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx

	/* If this changed %rcx, it was not canonical */
	cmpq	%rcx, %r11
	jne	opportunistic_sysret_failed

	cmpq	$__USER_CS, CS(%rsp)		/* CS must match SYSRET */
	jne	opportunistic_sysret_failed

	movq	R11(%rsp), %r11
	cmpq	%r11, EFLAGS(%rsp)		/* R11 == RFLAGS */
	jne	opportunistic_sysret_failed

	/*
	 * SYSCALL clears RF when it saves RFLAGS in R11 and SYSRET cannot
	 * restore RF properly. If the slowpath sets it for whatever reason, we
	 * need to restore it correctly.
	 *
	 * SYSRET can restore TF, but unlike IRET, restoring TF results in a
	 * trap from userspace immediately after SYSRET.  This would cause an
	 * infinite loop whenever #DB happens with register state that satisfies
	 * the opportunistic SYSRET conditions.  For example, single-stepping
	 * this user code:
	 *
	 *           movq	$stuck_here, %rcx
	 *           pushfq
	 *           popq %r11
	 *   stuck_here:
	 *
	 * would never get past 'stuck_here'.
	 */
	testq	$(X86_EFLAGS_RF|X86_EFLAGS_TF), %r11
	jnz	opportunistic_sysret_failed

	/* nothing to check for RSP */

	cmpq	$__USER_DS, SS(%rsp)		/* SS must match SYSRET */
	jne	opportunistic_sysret_failed

	/*
	 * We win! This label is here just for ease of understanding
	 * perf profiles. Nothing jumps here.
	 */
syscall_return_via_sysret:
	/* rcx and r11 are already restored (see code above) */
	RESTORE_C_REGS_EXCEPT_RCX_R11
	movq	RSP(%rsp), %rsp
	SWAPGS
	sysretq

opportunistic_sysret_failed:
	SWAPGS
	jmp	restore_c_regs_and_iret
END(entry_SYSCALL_64)

	/*
	 * Reload gs selector with exception handling
	 * edi:  new selector
	 */
ENTRY(native_load_gs_index)
	pushfq
	cli
	SWAPGS
.Lgs_change:
	movl	%edi, %gs
2:
	SWAPGS
	popfq
	ret
END(native_load_gs_index)

	_ASM_EXTABLE(.Lgs_change, bad_gs)
	.section .fixup, "ax"
	/* running with kernelgs */
bad_gs:
	SWAPGS					/* switch back to user gs */
.macro ZAP_GS
	/* This can't be a string because the preprocessor needs to see it. */
	movl $__USER_DS, %eax
	movl %eax, %gs
.endm
	ALTERNATIVE "", "ZAP_GS", X86_BUG_NULL_SEG
	xorl	%eax, %eax
	movl	%eax, %gs
	jmp	2b
	.previous

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
	ALLOC_PT_GPREGS_ON_STACK

	call	error_entry
	/* returned flag: ebx=0: need swapgs on exit, ebx=1: don't need it */

	movq	%rsp, %rdi		/* pt_regs pointer */

	.if \has_error_code
	movq	ORIG_RAX(%rsp), %rsi	/* get error code */
	movq	$-1, ORIG_RAX(%rsp)	/* no syscall to restart */
	.else
	xorl	%esi, %esi		/* no error code */
	.endif

	call	\do_sym

	jmp	error_exit
END(\sym)
.endm

/*
 * Save all registers in pt_regs, and switch gs if needed.
 * Return: EBX=0: came from user mode; EBX=1: otherwise
 */
ENTRY(error_entry)
	cld
	SAVE_C_REGS 8			/* offset 8 due to [call error_entry] pushes */
	SAVE_EXTRA_REGS 8
	xorl	%ebx, %ebx
	testb	$3, CS+8(%rsp)
	jz	.Lerror_kernelspace

	/*
	 * We entered from user mode or we're pretending to have entered
	 * from user mode due to an IRET fault.
	 */
	SWAPGS

.Lerror_entry_from_usermode_after_swapgs:
	ret

.Lerror_entry_done:
	ret

	/*
	 * There are two places in the kernel that can potentially fault with
	 * usergs. Handle them here.  B stepping K8s sometimes report a
	 * truncated RIP for IRET exceptions returning to compat mode. Check
	 * for these here too.
	 */
.Lerror_kernelspace:
	incl	%ebx
	leaq	native_irq_return_iret(%rip), %rcx
	cmpq	%rcx, RIP+8(%rsp)
	je	.Lerror_bad_iret
	movl	%ecx, %eax			/* zero extend */
	cmpq	%rax, RIP+8(%rsp)
	je	.Lbstep_iret
	cmpq	$.Lgs_change, RIP+8(%rsp)
	jne	.Lerror_entry_done

	/*
	 * hack: .Lgs_change can fail with user gsbase.  If this happens, fix up
	 * gsbase and proceed.  We'll fix up the exception and land in
	 * .Lgs_change's error handler with kernel gsbase.
	 */
	SWAPGS
	jmp .Lerror_entry_done

.Lbstep_iret:
	/* Fix truncated RIP */
	movq	%rcx, RIP+8(%rsp)
	/* fall through */

.Lerror_bad_iret:
	/*
	 * We came from an IRET to user mode, so we have user gsbase.
	 * Switch to kernel gsbase:
	 */
	SWAPGS

	/*
	 * Pretend that the exception came from user mode: set up pt_regs
	 * as if we faulted immediately after IRET and clear EBX so that
	 * error_exit knows that we will be returning to user mode.
	 */
	mov	%rsp, %rdi
	call	fixup_bad_iret
	mov	%rax, %rsp
	decl	%ebx
	jmp	.Lerror_entry_from_usermode_after_swapgs
END(error_entry)

/*
 * On entry, EBX is a "return to kernel mode" flag:
 *   1: already in kernel mode, don't need SWAPGS
 *   0: user gsbase is loaded, we need SWAPGS and standard preparation for return to usermode
 */
ENTRY(error_exit)
	movl	%ebx, %eax
	cli
	testl	%eax, %eax
	jnz	retint_kernel
	jmp	retint_user
END(error_exit)

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
.macro interrupt func
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
	SWAPGS

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

	pushq	%rdi

	call	\func			/* %rdi points to pt_regs */
.endm

/*
 * The interrupt stubs push (~vector+0x80) onto the stack
 * and then jump to common_interrupt.
 */
	.align 64
ENTRY(common_interrupt)
	/* Adjust vector to [-256, -1] range */
	addq	$-0x80, (%rsp)
	interrupt do_IRQ

	/* 0(%rsp): old RSP */
ret_from_intr:
	cli

	/* Restore saved previous stack */
	popq	%rsp

	testb	$3, CS(%rsp)
	jz	retint_kernel

	/* Interrupt came from user space */
retint_user:
	movq	%rsp, %rdi
	call	prepare_exit_to_usermode
	SWAPGS
	jmp	restore_regs_and_iret

	/* Returning to kernel space */
retint_kernel:
#ifdef CONFIG_PREEMPT
	/* Interrupts are off */
	/* Check if we need preemption */
	bt	$9, EFLAGS(%rsp)			/* was interrupt off? */
	jnc	1f
0:	cmpl	$0, PER_CPU_VAR(__preempt_count)	/* was preemption disabled? */
	jnz	1f
	GET_THREAD_INFO(%rcx)
	bt	$TIF_NEED_RESCHED, TI_flags(%rcx)	/* was need_resched set? */
	jnc	1f
	call	preempt_schedule_irq			/* Do preemption */
	jmp	0b
1:
#endif

/*
 * At this label, code paths which return to kernel and to user,
 * which come from interrupts/exception and from syscalls, merge.
 */
GLOBAL(restore_regs_and_iret)
	RESTORE_EXTRA_REGS
restore_c_regs_and_iret:
	RESTORE_C_REGS
	REMOVE_PT_GPREGS_FROM_STACK 8

.global native_irq_return_iret
native_irq_return_iret:
	/*
	 * The iretq could re-enable interrupts:
	 */
	/*
	 * This may fault.  Non-paranoid faults on return to userspace are
	 * handled by fixup_bad_iret.  These include #SS, #GP, and #NP.
	 * Double-faults due to espfix64 are handled in do_double_fault.
	 * Other faults here are fatal.
	 */
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
	interrupt \do_sym
	jmp	ret_from_intr
END(\smp__sym)
.endm

apicinterrupt RESCHEDULE_VECTOR			reschedule_interrupt		smp__reschedule_interrupt
apicinterrupt REBOOT_VECTOR			reboot_interrupt		smp__reboot_interrupt
apicinterrupt LOCAL_TIMER_VECTOR		apic_timer_interrupt		smp__apic_timer_interrupt
apicinterrupt X86_PLATFORM_IPI_VECTOR		x86_platform_ipi		smp__x86_platform_ipi
apicinterrupt CALL_FUNCTION_SINGLE_VECTOR	call_function_single_interrupt	smp__call_function_single_interrupt
apicinterrupt CALL_FUNCTION_VECTOR		call_function_interrupt		smp__call_function_interrupt
apicinterrupt ERROR_APIC_VECTOR			error_interrupt			smp__error_interrupt
apicinterrupt SPURIOUS_APIC_VECTOR		spurious_interrupt		smp__spurious_interrupt

/*
 * %rdi: prev task
 * %rsi: next task
 */
ENTRY(__switch_to_asm)
	/*
	 * Save callee-saved registers
	 * This must match the order in inactive_task_frame
	 *
	 * Note that ret_addr is already pushed:
	 *	1) context_switch(), where switch_to() was called
	 *	2) ret_from_fork(), which is placed by fork()
	 */
	pushq	%rbp
	pushq	%rbx
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15

	/* Switch stack */
	movq	%rsp, TASK_threadsp(%rdi)
	movq	TASK_threadsp(%rsi), %rsp

	/* restore callee-saved registers */
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbx
	popq	%rbp

	/*
	 * Note:
	 * This is a *JUMP* to __switch_to() function!
	 */
	jmp	__switch_to
END(__switch_to_asm)

/*
 * A newly forked process directly context switches into this address.
 *
 * rax: prev task we switched from
 * rbx: kernel thread func (NULL for user thread)
 * r12: kernel thread arg
 */
ENTRY(ret_from_fork)
	movq	%rax, %rdi
	call	schedule_tail		/* rdi: 'prev' task parameter */

	testq	%rbx, %rbx		/* from kernel_thread? */
	jnz	1f			/* kernel threads are uncommon */

2:
	movq    %rsp, %rdi
	call	syscall_return_slowpath	/* return with IRQs disabled */
	SWAPGS				/* switch to user gs.base */
	jmp	restore_regs_and_iret

1:
	/* kernel thread */
	movq	%r12, %rdi
	call	*%rbx
	/*
	 * A kernel thread is allowed to return here after successfully
	 * calling do_execve().  Exit to userspace to complete the execve()
	 * syscall:
	 */
	movq	$0, RAX(%rsp)
	jmp	2b
END(ret_from_fork)
