/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/asm.h>
#include <asm/page.h>
#include <asm/traps.h>
#include <asm/ptrace.h>
#include <asm/current.h>

#include <lego/sched.h>
#include <lego/kernel.h>

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

dotraplinkage void do_page_fault(struct pt_regs *regs, long error_code)
{
	struct task_struct *task;
	unsigned long address = read_cr2();

	task = current;

	show_fault_oops(task, regs, address);
	show_regs(regs);

	hlt();
}
