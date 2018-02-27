/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/asm.h>
#include <asm/msr.h>
#include <asm/page.h>
#include <asm/ptrace.h>
#include <asm/unwind.h>
#include <asm/stacktrace.h>

#include <lego/bug.h>
#include <lego/smp.h>
#include <lego/init.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/string.h>
#include <lego/utsname.h>

static char *exception_stack_names[N_EXCEPTION_STACKS] = {
		[ DOUBLEFAULT_STACK-1	]	= "#DF",
		[ NMI_STACK-1		]	= "NMI",
		[ DEBUG_STACK-1		]	= "#DB",
		[ MCE_STACK-1		]	= "#MC",
};

static void stack_type_str(enum stack_type type, const char **begin, const char **end)
{
	BUILD_BUG_ON(N_EXCEPTION_STACKS != 4);

	switch (type) {
	case STACK_TYPE_TASK:
		*begin = "TSK";
		*end   = "EOT";
		break;
	case STACK_TYPE_IRQ:
		*begin = "IRQ";
		*end   = "EOI";
		break;
	case STACK_TYPE_EXCEPTION ... STACK_TYPE_EXCEPTION_LAST:
		*begin = exception_stack_names[type - STACK_TYPE_EXCEPTION];
		*end   = "EOE";
		break;
	default:
		*begin = NULL;
		*end   = NULL;
	}
}

static bool in_task_stack(unsigned long *stack, struct task_struct *task,
			  struct stack_info *info)
{
	unsigned long *begin = task_stack_page(task);
	unsigned long *end = task_stack_page(task) + THREAD_SIZE;

	if (stack < begin || stack >= end)
		return false;

	info->type = STACK_TYPE_TASK;
	info->begin = begin;
	info->end = end;
	info->next_sp = NULL;

	return true;
}

static bool in_exception_stack(unsigned long *stack, struct stack_info *info)
{
	return false;
}

static bool in_irq_stack(unsigned long *stack, struct stack_info *info)
{
	return false;
}

int get_stack_info(unsigned long *stack, struct task_struct *task,
		   struct stack_info *info, unsigned long *visit_mask)
{
	if (!stack)
		goto unknown;

	task = task ? : current;

	if (in_task_stack(stack, task, info))
		goto recursion_check;

	if (task != current)
		goto unknown;

	if (in_exception_stack(stack, info))
		goto recursion_check;

	if (in_irq_stack(stack, info))
		goto recursion_check;

	goto unknown;

recursion_check:
	/*
	 * Make sure we don't iterate through any given stack more than once.
	 * If it comes up a second time then there's something wrong going on:
	 * just break out and report an unknown stack type.
	 */
	if (visit_mask) {
		if (*visit_mask & (1UL << info->type))
			goto unknown;
		*visit_mask |= 1UL << info->type;
	}

	return 0;

unknown:
	info->type = STACK_TYPE_UNKNOWN;
	return -EINVAL;
}

/**
 * Safely attempt to read from a location, protect from page-fault
 * @addr: address to read from
 * @retval: read into this variable
 *
 * Returns 0 on success, or -EFAULT.
 */
#define probe_kernel_address(addr, retval)		\
	probe_kernel_read(&retval, addr, sizeof(retval))

static inline long probe_kernel_read(void *dst, const void *src, size_t size)
{
	memcpy(dst, src, size);
	return 0;
}

void show_call_trace(struct task_struct *task, struct pt_regs *regs,
		     unsigned long *stack)
{
	struct unwind_state state;
	struct stack_info stack_info = {0};
	unsigned long visit_mask = 0;

	pr_info("Call Trace:\n");

	unwind_start(&state, task, regs, stack);

	/*
	 * Iterate through the stacks, starting with the current stack pointer.
	 * Each stack has a pointer to the next one.
	 *
	 * x86-64 can have several stacks:
	 * - (yes) task stack
	 * - (no)  interrupt stack
	 * - (no)  HW exception stacks (double fault, nmi, debug, mce)
	 */
	stack = stack ? : get_stack_pointer(task, regs);
	for (; stack; stack = stack_info.next_sp) {
		const char *str_begin, *str_end;

		/*
		 * If we overflowed the task stack into a guard page,
		 * jump back to the bottom of the usable stack.
		 */
		if (task_stack_page(task) - (void *)stack < PAGE_SIZE)
			stack = task_stack_page(task);

		if (get_stack_info(stack, task, &stack_info, &visit_mask))
			break;

		stack_type_str(stack_info.type, &str_begin, &str_end);
		if (str_begin)
			printk("<%s>\n", str_begin);

		/*
		 * Scan the stack, printing any text addresses we find.  At the
		 * same time, follow proper stack frames with the unwinder.
		 *
		 * Addresses found during the scan which are not reported by
		 * the unwinder are considered to be additional clues which are
		 * sometimes useful for debugging and are prefixed with '?'.
		 * This also serves as a failsafe option in case the unwinder
		 * goes off in the weeds.
		 */
		for (; stack < stack_info.end; stack++) {
			int reliable = 0;
			unsigned long addr = *stack;
			unsigned long *ret_addr_p =
				unwind_get_return_address_ptr(&state);

			if (!__kernel_text_address(addr))
				continue;

			if (stack == ret_addr_p)
				reliable = 1;

			printk("[<%p>] %s%pB\n",
				(void *)addr, reliable ? "" : "? ",
				(void *)addr);

			if (!reliable)
				continue;

			/*
			 * Get the next frame from the unwinder.  No need to
			 * check for an error: if anything goes wrong, the rest
			 * of the addresses will just be printed as unreliable.
			 */
			unwind_next_frame(&state);
		}

		if (str_end)
			printk("<%s>\n", str_end);
	}
}

static int stackslots_per_line = 4;
static int stack_lines = 5;

static int __init setup_stackslots_per_line(char *s)
{
	ssize_t ret;
	unsigned long val;

	if (!s)
		return -EINVAL;

	ret = kstrtoul(s, 0, &val);
	if (ret)
		return ret;
	stackslots_per_line = val;
	return 0;
}
__setup("stackslots_per_line", setup_stackslots_per_line);

static int __init setup_stack_lines(char *s)
{
	ssize_t ret;
	unsigned long val;

	if (!s)
		return -EINVAL;

	ret = kstrtoul(s, 0, &val);
	if (ret)
		return ret;
	stack_lines = val;
	return 0;
}
__setup("stack_lines", setup_stack_lines);

void show_stack_content(struct task_struct *task, struct pt_regs *regs,
			unsigned long *sp)
{
	int i, kstack_depth_to_print;
	unsigned long *stack;

	pr_info("Stack:\n");

	kstack_depth_to_print = stackslots_per_line * stack_lines;

	sp = sp ? : get_stack_pointer(task, regs);
	stack = sp;
	for (i = 0; i < kstack_depth_to_print; i++) {
		unsigned long word;

		if (kstack_end(stack))
			break;

		probe_kernel_address(stack, word);
		if ((i % stackslots_per_line) == 0) {
			if (i != 0)
				pr_cont("\n");
			pr_info("%016lx", word);
		} else
			pr_cont(" %016lx", word);

		stack++;
	}
	pr_cont("\n");
}

#define CODE_BYTES		64
#define CODE_PROLOGUE_BYTES	43

static void show_code(struct pt_regs *regs)
{
	unsigned int code_prologue = CODE_PROLOGUE_BYTES;
	unsigned int code_len = CODE_BYTES;
	unsigned char c;
	u8 *ip;
	int i;

	pr_info("Code: ");
	ip = (u8 *)regs->ip - code_prologue;
	if (ip < (u8 *)START_KERNEL || probe_kernel_address(ip, c)) {
		/* try starting at IP */
		ip = (u8 *)regs->ip;
		code_len = code_len - code_prologue + 1;
	}

	for (i = 0; i < code_len; i++, ip++) {
		if (ip < (u8 *)START_KERNEL || probe_kernel_address(ip, c)) {
			pr_cont(" Bad RIP value.");
			break;
		}
		if (ip == (u8 *)regs->ip)
			pr_cont("<%02x> ", c);
		else
			pr_cont("%02x ", c);
	}
	pr_cont("\n");
}

void __show_regs(struct pt_regs *regs, int all)
{
	unsigned long cr0 = 0L, cr2 = 0L, cr3 = 0L, cr4 = 0L, fs, gs, shadowgs;
	unsigned int fsindex, gsindex;
	unsigned int ds, cs, es;

	printk(KERN_DEFAULT "RIP: %04lx:[<%016lx>] ", regs->cs & 0xffff, regs->ip);
	printk(KERN_CONT    " [<%p>] %pS\n", (void *)regs->ip, (void *)regs->ip);
	printk(KERN_DEFAULT "RSP: %04lx:%016lx  EFLAGS: %08lx\n", regs->ss,
			regs->sp, regs->flags);
	printk(KERN_DEFAULT "RAX: %016lx RBX: %016lx RCX: %016lx\n",
	       regs->ax, regs->bx, regs->cx);
	printk(KERN_DEFAULT "RDX: %016lx RSI: %016lx RDI: %016lx\n",
	       regs->dx, regs->si, regs->di);
	printk(KERN_DEFAULT "RBP: %016lx R08: %016lx R09: %016lx\n",
	       regs->bp, regs->r8, regs->r9);
	printk(KERN_DEFAULT "R10: %016lx R11: %016lx R12: %016lx\n",
	       regs->r10, regs->r11, regs->r12);
	printk(KERN_DEFAULT "R13: %016lx R14: %016lx R15: %016lx\n",
	       regs->r13, regs->r14, regs->r15);

	asm("movl %%ds,%0" : "=r" (ds));
	asm("movl %%cs,%0" : "=r" (cs));
	asm("movl %%es,%0" : "=r" (es));
	asm("movl %%fs,%0" : "=r" (fsindex));
	asm("movl %%gs,%0" : "=r" (gsindex));

	rdmsrl(MSR_FS_BASE, fs);
	rdmsrl(MSR_GS_BASE, gs);
	rdmsrl(MSR_KERNEL_GS_BASE, shadowgs);

	if (!all)
		return;

	cr0 = read_cr0();
	cr2 = read_cr2();
	cr3 = read_cr3();
	cr4 = read_cr4();

	printk(KERN_DEFAULT "FS:  %016lx(%04x) GS:%016lx(%04x) knlGS:%016lx\n",
	       fs, fsindex, gs, gsindex, shadowgs);
	printk(KERN_DEFAULT "CS:  %04x DS: %04x ES: %04x CR0: %016lx\n", cs, ds,
			es, cr0);
	printk(KERN_DEFAULT "CR2: %016lx CR3: %016lx CR4: %016lx\n", cr2, cr3,
			cr4);
}

void show_general_task_info(struct task_struct *task)
{
	pr_info("CPU: %d PID: %d Comm: %.16s %s %.*s\n",
		smp_processor_id(), current->pid, current->comm,
		utsname.release,
		(int)strcspn(utsname.version, " "),
		utsname.version);
}

/* Both task and regs can be NULL */
void show_regs(struct pt_regs *regs)
{
	struct task_struct *task = current;

	show_general_task_info(task);

	__show_regs(regs, 1);

	/* print stack, calltrace and code if in kernel mode */
	if (!user_mode(regs)) {
		show_stack_content(current, regs, NULL);
		show_call_trace(current, regs, NULL);
		show_code(regs);
	}
}

void show_stack(struct task_struct *task, unsigned long *sp)
{
	task = task ? : current;

	/*
	 * Stack frames below this one aren't interesting.
	 * Don't show them if we're printing for %current.
	 */
	if (!sp && task == current)
		sp = get_stack_pointer(current, NULL);

	show_stack_content(task, NULL, sp);
}
