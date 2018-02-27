/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/panic.h>
#include <lego/printk.h>
#include <lego/kernel.h>
#include <lego/signal.h>
#include <lego/linkage.h>

#include <asm/desc.h>
#include <asm/traps.h>
#include <asm/ptrace.h>
#include <asm/kdebug.h>
#include <asm/syscalls.h>
#include <asm/irq_vectors.h>
#include <asm/fpu/internal.h>

#define print_trap()							\
	pr_crit("TRAP %s in CPU%d, error_code: %ld current:%p %d %s\n",	\
		__func__, smp_processor_id(), error_code,		\
		current, current->pid, current->comm)

#ifdef CONFIG_X86_DEBUG_TRAP
#define debug_print_trap()	print_trap
#else
static inline void debug_print_trap(void) { }
#endif

/*
 * The default IDT table
 * Filled during early boot and will NOT be changed afterwards.
 */
gate_desc idt_table[NR_VECTORS];

int first_system_vector = FIRST_SYSTEM_VECTOR;
DECLARE_BITMAP(used_vectors, NR_VECTORS);

struct desc_ptr idt_desc = {
	.size = NR_VECTORS * 16 - 1,
	.address = (unsigned long)idt_table,
};

static inline void cond_local_irq_enable(struct pt_regs *regs)
{
	if (regs->flags & X86_EFLAGS_IF)
		local_irq_enable();
}

static inline void cond_local_irq_disable(struct pt_regs *regs)
{
	if (regs->flags & X86_EFLAGS_IF)
		local_irq_disable();
}

struct bad_iret_stack {
	void *error_entry_ret;
	struct pt_regs regs;
};

asmlinkage __visible
struct bad_iret_stack *fixup_bad_iret(struct bad_iret_stack *s)
{
	/*
	 * This is called from entry_64.S early in handling a fault
	 * caused by a bad iret to user mode.  To handle the fault
	 * correctly, we want move our stack frame to task_pt_regs
	 * and we want to pretend that the exception came from the
	 * iret target.
	 */
	struct bad_iret_stack *new_stack =
		container_of(task_pt_regs(current),
			     struct bad_iret_stack, regs);

	WARN(1, "Bad IRET, bug?");

	/* Copy the IRET target to the new stack. */
	memmove(&new_stack->regs.ip, (void *)s->regs.sp, 5*8);

	/* Copy the remainder of the stack from the current stack. */
	memmove(new_stack, s, offsetof(struct bad_iret_stack, regs.ip));

	BUG_ON(!user_mode(&new_stack->regs));
	return new_stack;
}

static int
do_trap_no_signal(struct task_struct *tsk, int trapnr, char *str,
		  struct pt_regs *regs,	long error_code)
{
	if (!user_mode(regs)) {
		if (!fixup_exception(regs, trapnr)) {
			tsk->thread.error_code = error_code;
			tsk->thread.trap_nr = trapnr;
			die(str, regs, error_code);
		}
		return 0;
	}
	return -1;
}

static siginfo_t *fill_trap_info(struct pt_regs *regs, int signr, int trapnr,
				siginfo_t *info)
{
	unsigned long siaddr;
	int sicode;

	switch (trapnr) {
	default:
		return SEND_SIG_PRIV;

	case X86_TRAP_DE:
		sicode = FPE_INTDIV;
		siaddr = 0;
		break;
	case X86_TRAP_UD:
		sicode = ILL_ILLOPN;
		siaddr = 0;
		break;
	case X86_TRAP_AC:
		sicode = BUS_ADRALN;
		siaddr = 0;
		break;
	}

	info->si_signo = signr;
	info->si_errno = 0;
	info->si_code = sicode;
	info->si_addr = (void __user *)siaddr;
	return info;
}

static void
do_trap(int trapnr, int signr, char *str, struct pt_regs *regs,
	long error_code, siginfo_t *info)
{
	struct task_struct *tsk = current;

	if (!do_trap_no_signal(tsk, trapnr, str, regs, error_code))
		return;

	/*
	 * We want error_code and trap_nr set for userspace faults and
	 * kernelspace faults which result in die(), but not
	 * kernelspace faults which are fixed up.  die() gives the
	 * process no chance to handle the signal and notice the
	 * kernel fault information, so that won't result in polluting
	 * the information about previously queued, but not yet
	 * delivered, faults.  See also do_general_protection below.
	 */
	tsk->thread.error_code = error_code;
	tsk->thread.trap_nr = trapnr;

	pr_info("%s[%d] trap %s ip:%lx sp:%lx error:%lx\n",
		tsk->comm, tsk->pid, str,
		regs->ip, regs->sp, error_code);

	force_sig_info(signr, info ?: SEND_SIG_PRIV, tsk);
}

static void do_error_trap(struct pt_regs *regs, long error_code, char *str,
			  unsigned long trapnr, int signr)
{
	siginfo_t info;

	debug_print_trap();

	cond_local_irq_enable(regs);
	do_trap(trapnr, signr, str, regs, error_code,
		fill_trap_info(regs, signr, trapnr, &info));
}

#define DO_ERROR_TRAP(str, name, trapnr, signr)				\
dotraplinkage void do_##name(struct pt_regs *regs, long error_code)	\
{									\
	do_error_trap(regs, error_code, str, trapnr, signr);		\
}

DO_ERROR_TRAP("divide error",		     divide_error,		  X86_TRAP_DE,	   SIGFPE  )
DO_ERROR_TRAP("debug",			     debug,			  X86_TRAP_DB,	   SIGTRAP )
DO_ERROR_TRAP("int3",			     int3,			  X86_TRAP_BP,	   SIGTRAP )
DO_ERROR_TRAP("overflow",     		     overflow,			  X86_TRAP_OF,	   SIGSEGV )
DO_ERROR_TRAP("bounds",			     bounds,			  X86_TRAP_BR,	   SIGSEGV )
DO_ERROR_TRAP("invalid opcode",		     invalid_op,		  X86_TRAP_UD,	   SIGILL  )
DO_ERROR_TRAP("invalid TSS",		     invalid_TSS,		  X86_TRAP_TS,	   SIGSEGV )
DO_ERROR_TRAP("segment not present",	     segment_not_present,	  X86_TRAP_NP,	   SIGBUS  )
DO_ERROR_TRAP("stack segment",		     stack_segment,		  X86_TRAP_SS,	   SIGBUS  )
DO_ERROR_TRAP("alignment check",	     alignment_check,		  X86_TRAP_AC,	   SIGBUS  )
DO_ERROR_TRAP("coprocessor segment overrun", coprocessor_segment_overrun, X86_TRAP_OLD_MF, SIGFPE  )

dotraplinkage void do_general_protection(struct pt_regs *regs, long error_code)
{
	struct task_struct *tsk = current;

	debug_print_trap();

	cond_local_irq_enable(regs);
	if (!user_mode(regs)) {
		if (fixup_exception(regs, X86_TRAP_GP))
			return;

		tsk->thread.error_code = error_code;
		tsk->thread.trap_nr = X86_TRAP_GP;
		die("general protection fault", regs, error_code);
		return;
	}

	tsk->thread.error_code = error_code;
	tsk->thread.trap_nr = X86_TRAP_GP;

	pr_info("%s[%d] general protection ip:%lx sp:%lx error:%lx\n",
		tsk->comm, tsk->pid, regs->ip, regs->sp, error_code);
	show_regs(regs);

	/* Print short info about all tasks */
	show_state_filter(0, false);

	force_sig_info(SIGSEGV, SEND_SIG_PRIV, tsk);
}

dotraplinkage void do_device_not_available(struct pt_regs *regs, long error_code)
{
	print_trap();
	fpu__restore(&current->thread.fpu); /* interrupts still off */
}

dotraplinkage void do_spurious_interrupt_bug(struct pt_regs *regs, long error_code)
{
	print_trap();
	cond_local_irq_enable(regs);
}

/*
 * Note that we play around with the 'TS' bit in an attempt to get
 * the correct behaviour even in the presence of the asynchronous
 * IRQ13 behaviour
 */
static void math_error(struct pt_regs *regs, int error_code, int trapnr)
{
	struct task_struct *task = current;
	struct fpu *fpu = &task->thread.fpu;
	siginfo_t info;
	char *str = (trapnr == X86_TRAP_MF) ? "fpu exception" : "simd exception";

	cond_local_irq_enable(regs);

	if (!user_mode(regs)) {
		if (!fixup_exception(regs, trapnr)) {
			task->thread.error_code = error_code;
			task->thread.trap_nr = trapnr;
			die(str, regs, error_code);
		}
		return;
	}

	/*
	 * Save the info for the exception handler and clear the error.
	 */
	fpu__save(fpu);

	task->thread.trap_nr	= trapnr;
	task->thread.error_code = error_code;
	info.si_signo		= SIGFPE;
	info.si_errno		= 0;
	info.si_addr		= (void __user *)GET_IP(regs);

	info.si_code = fpu__exception_code(fpu, trapnr);

	/* Retry when we get spurious exceptions: */
	if (!info.si_code)
		return;

	force_sig_info(SIGFPE, &info, task);
}

dotraplinkage void
do_simd_exception(struct pt_regs *regs, long error_code)
{
	print_trap();
	math_error(regs, error_code, X86_TRAP_XF);
}

dotraplinkage void do_coprocessor_error(struct pt_regs *regs, long error_code)
{
	print_trap();
	math_error(regs, error_code, X86_TRAP_MF);
}

dotraplinkage void do_double_fault(struct pt_regs *regs, long error_code)
{
	pr_emerg("PANIC: double fault, error_code: 0x%lx\n", error_code);
	show_regs(regs);
	panic("Machine halted.");
}

dotraplinkage void do_machine_check(struct pt_regs *regs, long error_code)
{
	pr_emerg("PANIC: machine check, error_code: 0x%lx\n", error_code);
	show_regs(regs);
	panic("Machine halted.");
}

dotraplinkage void do_virtualization_exception(struct pt_regs *regs, long error_code)
{
	pr_emerg("PANIC: virtualization exception, error_code: 0x%lx\n", error_code);
	show_regs(regs);
	panic("Machine halted.");
}

dotraplinkage void do_reserved(struct pt_regs *regs, long error_code)
{
	pr_emerg("PANIC: reserved exception, error_code: 0x%lx\n", error_code);
	show_regs(regs);
	panic("Machine halted.");
}

/* TODO */
dotraplinkage void do_nmi(struct pt_regs *regs, long error_code)
{
	print_trap();
	for(;;)
		hlt();
}

void __init trap_init(void)
{
	int i;

	set_intr_gate(X86_TRAP_DE, divide_error);
	set_intr_gate(X86_TRAP_DB, debug);
	set_intr_gate(X86_TRAP_NMI, nmi);
	set_intr_gate(X86_TRAP_BP, int3);
	set_intr_gate(X86_TRAP_OF, overflow);
	set_intr_gate(X86_TRAP_BR, bounds);
	set_intr_gate(X86_TRAP_UD, invalid_op);
	set_intr_gate(X86_TRAP_NM, device_not_available);
	set_intr_gate(X86_TRAP_DF, double_fault);
	set_intr_gate(X86_TRAP_OLD_MF, coprocessor_segment_overrun);
	set_intr_gate(X86_TRAP_TS, invalid_TSS);
	set_intr_gate(X86_TRAP_NP, segment_not_present);
	set_intr_gate(X86_TRAP_SS, stack_segment);
	set_intr_gate(X86_TRAP_GP, general_protection);
	set_intr_gate(X86_TRAP_PF, page_fault);
	set_intr_gate(X86_TRAP_SPURIOUS, spurious_interrupt_bug);
	set_intr_gate(X86_TRAP_MF, coprocessor_error);
	set_intr_gate(X86_TRAP_AC, alignment_check);
	set_intr_gate(X86_TRAP_MC, machine_check);
	set_intr_gate(X86_TRAP_XF, simd_exception);
	set_intr_gate(X86_TRAP_VE, virtualization_exception);

	for (i = 0; i < FIRST_EXTERNAL_VECTOR; i++)
		set_bit(i, used_vectors);

#ifdef CONFIG_IA32_EMULATION
	set_system_intr_gate(IA32_SYSCALL_VECTOR, entry_INT80_compat);
	set_bit(IA32_SYSCALL_VECTOR, used_vectors);
#endif

	load_idt((const struct desc_ptr *)&idt_desc);
}
