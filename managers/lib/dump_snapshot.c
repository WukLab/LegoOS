/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* Ugh.. */

#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/checkpoint.h>

void dump_process_snapshot_files(struct process_snapshot *pss)
{
	int i;
	struct ss_files *f, *ss_files = pss->files;

	pr_debug(" Files (nr_files: %d)\n", pss->nr_files);
	for (i = 0; i < pss->nr_files; i++) {
		f = &ss_files[i];

		pr_debug("  fd=%d, f_name: %s\n", f->fd, f->f_name);
		pr_debug("     f_mode:%x,f_flags:%x,f_pos:%lx\n",
			f->f_mode, f->f_flags, f->f_pos);
	}
}

void dump_process_snapshot_signals(struct process_snapshot *pss)
{
	struct sigaction *action;
	int i;

	pr_debug(" Blocked signals: %lx\n", pss->blocked.sig[0]);
	pr_debug(" SigActions: \n");
	for (i = 0; i < _NSIG; i++) {
		action = &pss->action[i];

		pr_debug("  signr: %d\n", i + 1);
		dump_sigaction(action, "    ");
	}
}

static void dump_thread_registers(struct ss_task_struct *t)
{
	struct ss_thread_gregs *regs = &t->user_regs.gregs;

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
	pr_debug("  FS:  %016lx(%04lx) GS:%016lx(%04lx)\n",
		regs->fs_base, regs->fs, regs->gs_base, regs->gs);
	pr_debug("  CS:  %04lx DS: %04lx ES: %04lx\n",
		regs->cs, regs->ds, regs->es);
}

void dump_process_snapshot_thread(struct ss_task_struct *t)
{
	pr_debug("  pid: %d, set_child_tid: %p, clear_child_tid: %p\n",
		t->pid, t->set_child_tid, t->clear_child_tid);
	pr_debug("  sas_ss_sp: %#lx, sas_ss_size: %#lx, sas_ss_flags: %#x\n",
		t->sas_ss_sp, t->sas_ss_size, t->sas_ss_flags);
	dump_thread_registers(t);
}

void dump_process_snapshot_threads(struct process_snapshot *pss)
{
	struct ss_task_struct *task, *tasks = pss->tasks;
	int i;

	for (i = 0; i < pss->nr_tasks; i++) {
		task = &tasks[i];
		pr_debug(" Thread_%d\n", i);
		dump_process_snapshot_thread(task);
	}
}

void dump_process_snapshot(struct process_snapshot *pss, const char *who,
			   int dump_flags)
{
	if (!pss || !who) {
		pr_err("Need both @pss and @who!");
		return;
	}

	pr_debug("Snapshot Dumper (called by %s)\n", who);
	pr_debug(" nr_tasks: %u\n", pss->nr_tasks);
	pr_debug(" comm: %s\n", pss->comm);

	dump_process_snapshot_threads(pss);
	dump_process_snapshot_files(pss);

	if (dump_flags & DUMP_SS_SIGNAL)
		dump_process_snapshot_signals(pss);
}
