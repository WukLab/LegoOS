/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/asm.h>
#include <asm/page.h>
#include <asm/traps.h>
#include <asm/current.h>

#include <lego/mm.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/ptrace.h>

/*
 * Page fault error code bits:
 *
 *   bit 0 ==	 0: no page found	1: protection fault
 *   bit 1 ==	 0: read access		1: write access
 *   bit 2 ==	 0: kernel-mode access	1: user-mode access
 *   bit 3 ==				1: use of reserved bit detected
 *   bit 4 ==				1: fault was an instruction fetch
 *   bit 5 ==				1: protection keys block access
 */
enum x86_pf_error_code {
	PF_PROT		=		1 << 0,
	PF_WRITE	=		1 << 1,
	PF_USER		=		1 << 2,
	PF_RSVD		=		1 << 3,
	PF_INSTR	=		1 << 4,
	PF_PK		=		1 << 5,
};

static int fault_in_kernel_space(unsigned long address)
{
	return address >= TASK_SIZE_MAX;
}

static void show_fault_oops(struct task_struct *task, struct pt_regs *regs, unsigned long address)
{
	printk(KERN_ALERT "BUG: unable to handle kernel ");
	if (address < PAGE_SIZE)
		printk(KERN_CONT "NULL pointer dereference");
	else
		printk(KERN_CONT "paging request");

	printk(KERN_CONT   " at %p\n", (void *)address);
	printk(KERN_ALERT "IP: [<%p>] %pS\n", (void *)address, (void *)address);
}

/*
 * This routine handles page faults.  It determines the address,
 * and the problem, and then passes it off to one of the appropriate
 * routines.
 */
dotraplinkage void do_page_fault(struct pt_regs *regs, long error_code)
{
	struct task_struct *tsk = current;
	unsigned long address = read_cr2();

	if (user_mode(regs)) {
		pr_info("Faulting from usermode\n");
		show_regs(regs);
	}

	if (fault_in_kernel_space(address) && !user_mode(regs)) {
		show_fault_oops(tsk, regs, address);
		show_regs(regs);
	}

	hlt();
}
