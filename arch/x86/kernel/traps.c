/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/desc.h>
#include <asm/traps.h>
#include <asm/ptrace.h>
#include <asm/irq_vectors.h>

#include <lego/sched.h>
#include <lego/panic.h>
#include <lego/printk.h>
#include <lego/kernel.h>
#include <lego/signal.h>
#include <lego/linkage.h>
#include <lego/compiler.h>

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

static void do_error_trap(struct pt_regs *regs, long error_code, char *str,
			  unsigned long trapnr, int signr)
{
	printk("%s, trapnr=%lu\n", str, trapnr);
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
DO_ERROR_TRAP("simd exception",		     simd_exception,		  X86_TRAP_XF,	   SIGSEGV )
DO_ERROR_TRAP("coprocessor segment overrun", coprocessor_segment_overrun, X86_TRAP_OLD_MF, SIGFPE  )

dotraplinkage void do_general_protection(struct pt_regs *regs, long error_code)
{
	show_regs(regs);
	printk("#GP");
}

dotraplinkage void do_nmi(struct pt_regs *regs, long error_code)
{
	show_regs(regs);
	printk("NMI");
}

dotraplinkage void do_device_not_available(struct pt_regs *regs, long error_code)
{
	show_regs(regs);
	printk("Device Not Avaliable");
}

dotraplinkage void do_double_fault(struct pt_regs *regs, long error_code)
{
	show_regs(regs);
	printk("Double Fault");
}

dotraplinkage void do_spurious_interrupt_bug(struct pt_regs *regs, long error_code)
{
	show_regs(regs);
	printk("Spurious Interrupt Bug");
}

dotraplinkage void do_coprocessor_error(struct pt_regs *regs, long error_code)
{
	show_regs(regs);
	printk("X87 Coprocessor Error");
}

dotraplinkage void do_machine_check(struct pt_regs *regs, long error_code)
{
	show_regs(regs);
	printk("Machine Check");
}

dotraplinkage void do_virtualization_exception(struct pt_regs *regs, long error_code)
{
	show_regs(regs);
	printk("Virtualization Exception");
}

dotraplinkage void do_reserved(struct pt_regs *regs, long error_code)
{
	show_regs(regs);
	printk("Reserved Interrupt");
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

	load_idt((const struct desc_ptr *)&idt_desc);
}
