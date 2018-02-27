/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/ptrace.h>
#include <lego/extable.h>
#include <asm/traps.h>

#ifdef CONFIG_X86_DEBUG_FIXUP_EXCEPTION
#define fixup_debug(fmt, ...)					\
	pr_debug("fixup_exception pid(%d) cpu(%d) " fmt "\n",	\
		current->pid, smp_processor_id(), __VA_ARGS__)
#else
#define fixup_debug(fmt, ...)	do { } while(0)
#endif

typedef bool (*ex_handler_t)(const struct exception_table_entry *,
			    struct pt_regs *, int);

/*
 * Add the current offset to the saved address.
 * This is because we have minused that in _ASM_EXTABLE macro.
 * We do this so x86-64 can also use 4 bytes to save address.
 *		- ys
 */
static inline unsigned long
ex_fixup_insn(const struct exception_table_entry *x)
{
	return (unsigned long)&x->insn + x->insn;
}

static inline unsigned long
ex_fixup_addr(const struct exception_table_entry *x)
{
	return (unsigned long)&x->fixup + x->fixup;
}

static inline ex_handler_t
ex_fixup_handler(const struct exception_table_entry *x)
{
	return (ex_handler_t)((unsigned long)&x->handler + x->handler);
}

bool ex_handler_default(const struct exception_table_entry *fixup,
		       struct pt_regs *regs, int trapnr)
{
	regs->ip = ex_fixup_addr(fixup);
	return true;
}

bool ex_handler_fault(const struct exception_table_entry *fixup,
		     struct pt_regs *regs, int trapnr)
{
	regs->ip = ex_fixup_addr(fixup);
	regs->ax = trapnr;
	return true;
}

bool ex_handler_ext(const struct exception_table_entry *fixup,
		   struct pt_regs *regs, int trapnr)
{
	/* Special hack for uaccess_err */
	current->thread.uaccess_err = 1;
	regs->ip = ex_fixup_addr(fixup);
	return true;
}

bool ex_handler_rdmsr_unsafe(const struct exception_table_entry *fixup,
			     struct pt_regs *regs, int trapnr)
{
	if (pr_warn("unchecked MSR access error: RDMSR from 0x%x at rIP: 0x%lx (%pF)\n",
			 (unsigned int)regs->cx, regs->ip, (void *)regs->ip))
		show_regs(regs);

	/* Pretend that the read succeeded and returned 0. */
	regs->ip = ex_fixup_addr(fixup);
	regs->ax = 0;
	regs->dx = 0;
	return true;
}

bool ex_handler_wrmsr_unsafe(const struct exception_table_entry *fixup,
			     struct pt_regs *regs, int trapnr)
{
	if (pr_warn("unchecked MSR access error: WRMSR to 0x%x (tried to write 0x%08x%08x) at rIP: 0x%lx (%pF)\n",
			 (unsigned int)regs->cx, (unsigned int)regs->dx,
			 (unsigned int)regs->ax,  regs->ip, (void *)regs->ip))
		show_regs(regs);

	/* Pretend that the write succeeded. */
	regs->ip = ex_fixup_addr(fixup);
	return true;
}

int fixup_exception(struct pt_regs *regs, int trapnr)
{
	const struct exception_table_entry *e;
	ex_handler_t handler;

	e = search_exception_tables(regs->ip);
	if (!e)
		return 0;

	fixup_debug("insn:%#lx(%pF) fixup:%#lx(%pF) handler:%pF",
		ex_fixup_insn(e), (void *)ex_fixup_insn(e),
		ex_fixup_addr(e), (void *)ex_fixup_addr(e),
		(void *)ex_fixup_handler(e));

	handler = ex_fixup_handler(e);
	return handler(e, regs, trapnr);
}

extern unsigned int early_recursion_flag;

/* Restricted version used during very early boot */
void __init early_fixup_exception(struct pt_regs *regs, int trapnr)
{
	printk("%s: 0x%02x IP %lx:%lx error %lx cr2 0x%lx\n",
		__func__, (unsigned)trapnr, (unsigned long)regs->cs, regs->ip,
		regs->orig_ax, read_cr2());

	/* Ignore early NMIs. */
	if (trapnr == X86_TRAP_NMI)
		return;

	if (early_recursion_flag > 2)
		goto halt_loop;

	/*
	 * Old CPUs leave the high bits of CS on the stack
	 * undefined.  I'm not sure which CPUs do this, but at least
	 * the 486 DX works this way.
	 */
	if ((regs->cs & 0xFFFF) != __KERNEL_CS)
		goto fail;

	/*
	 * The full exception fixup machinery is available as soon as
	 * the early IDT is loaded.  This means that it is the
	 * responsibility of extable users to either function correctly
	 * when handlers are invoked early or to simply avoid causing
	 * exceptions before they're ready to handle them.
	 *
	 * This is better than filtering which handlers can be used,
	 * because refusing to call a handler here is guaranteed to
	 * result in a hard-to-debug panic.
	 *
	 * Keep in mind that not all vectors actually get here.  Early
	 * page faults, for example, are special.
	 */
	if (fixup_exception(regs, trapnr))
		return;

fail:
	show_regs(regs);

halt_loop:
	while (true)
		halt();
}
