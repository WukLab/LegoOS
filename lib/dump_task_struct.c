/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/kernel.h>

static void dump_task_struct_thread_registers(struct task_struct *t)
{
	struct pt_regs *regs = task_pt_regs(t);

	pr_debug(" Top pt_regs:\n");
	pr_debug("  RIP: %04lx:[<%016lx>] ", regs->cs & 0xffff, regs->ip);
	pr_cont(" [<%p>] %pS\n", (void *)regs->ip, (void *)regs->ip);
	pr_debug("  RSP: %04lx:%016lx  EFLAGS: %08lx\n", regs->ss,
		regs->sp, regs->flags);
	pr_debug("  RAX: %016lx RBX: %016lx RCX: %016lx\n",
		regs->ax, regs->bx, regs->cx);
	pr_debug("  RDX: %016lx RSI: %016lx RDI: %016lx\n",
		regs->dx, regs->si, regs->di);
	pr_debug("  RBP: %016lx R08: %016lx R09: %016lx\n",
		regs->bp, regs->r8, regs->r9);
	pr_debug("  R10: %016lx R11: %016lx R12: %016lx\n",
		regs->r10, regs->r11, regs->r12);
	pr_debug("  R13: %016lx R14: %016lx R15: %016lx\n",
		regs->r13, regs->r14, regs->r15);
	pr_debug("  FS:  %016lx(%04x) GS:%016lx(%04x)\n",
	       t->thread.fsbase, 0, t->thread.gsbase, 0);
}

static void dump_task_struct_thread(struct task_struct *t)
{
	pr_debug("  pid: %d, set_child_tid: %p, clear_child_tid: %p\n",
		t->pid, t->set_child_tid, t->clear_child_tid);
	pr_debug("  sas_ss_sp: %#lx, sas_ss_size: %#lx, sas_ss_flags: %#x\n",
		t->sas_ss_sp, t->sas_ss_size, t->sas_ss_flags);

	dump_task_struct_thread_registers(t);
}

static void dump_task_struct_threads(struct task_struct *p)
{
	unsigned long flags;
	struct task_struct *t;
	int i = 0;

	spin_lock_irqsave(&tasklist_lock, flags);
	for_each_thread(p, t) {
		pr_debug(" Thread_%d\n", i++);
		dump_task_struct_thread(t);
	}
	spin_unlock_irqrestore(&tasklist_lock, flags);
}

static void dump_task_struct_files(struct task_struct *p)
{
	struct file *f;
	struct files_struct *files = p->files;
	int fd;

	pr_debug(" Files:\n");
	spin_lock(&files->file_lock);
	for_each_set_bit(fd, files->fd_bitmap, NR_OPEN_DEFAULT) {
		f = files->fd_array[fd];
		BUG_ON(!f);

		pr_debug("  fd=%d, f_name: %s\n", fd, f->f_name);
		pr_debug("     f_mode:%x,f_flags:%x,f_pos:%Lx\n",
			f->f_mode, f->f_flags, f->f_pos);
	}
	spin_unlock(&files->file_lock);
}

static void dump_task_struct_signals(struct task_struct *p)
{
	struct sigaction *action;
	int i;

	pr_debug(" Blocked signals: %lx\n", p->blocked.sig[0]);
	pr_debug(" SigActions: \n");
	for (i = 0; i < _NSIG; i++) {
		action = &p->sighand->action[i].sa;

		pr_debug("  signr: %d\n", i + 1);
		dump_sigaction(action, "    ");
	}
}

void dump_task_struct(struct task_struct *p, int dump_flags)
{
	if (!p)
		return;

	pr_debug("task_struct Dumper\n");
	pr_debug(" tgid: %u\n", p->tgid);
	pr_debug(" nr_threads: %u\n", p->signal->nr_threads);
	pr_debug(" comm: %s\n", p->comm);

	dump_task_struct_threads(p);
	dump_task_struct_files(p);

	if (dump_flags & DUMP_TASK_STRUCT_SIGNAL)
		dump_task_struct_signals(p);
}
