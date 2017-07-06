/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/sched.h>
#include <lego/ptrace.h>
#include <lego/kernel.h>
#include <lego/binfmts.h>
#include <lego/spinlock.h>
#include <lego/syscalls.h>

static LIST_HEAD(formats);
static DEFINE_SPINLOCK(binfmt_lock);

void __register_binfmt(struct lego_binfmt *fmt, int insert)
{
	BUG_ON(!fmt);
	if (WARN_ON(!fmt->load_binary))
		return;
	spin_lock(&binfmt_lock);
	insert ? list_add(&fmt->lh, &formats) :
		 list_add_tail(&fmt->lh, &formats);
	spin_unlock(&binfmt_lock);
}

void unregister_binfmt(struct lego_binfmt *fmt)
{
	spin_lock(&binfmt_lock);
	list_del(&fmt->lh);
	spin_unlock(&binfmt_lock);
}

static int exec_mmap(void)
{
	struct mm_struct *new_mm;
	struct mm_struct *old_mm;
	struct task_struct *tsk;

	new_mm = mm_alloc();
	if (!new_mm)
		return -ENOMEM;

	tsk = current;
	old_mm = current->mm;
	mm_release(tsk, old_mm);

	task_lock(tsk);
	tsk->mm = new_mm;
	tsk->active_mm = new_mm;
	activate_mm(old_mm, new_mm);
	task_unlock(tsk);

	if (old_mm)
		mmput(old_mm);
	return 0;
}

int do_execve(const char *filename,
	      const char * const *argv,
	      const char * const *envp)
{
	struct pt_regs *regs = current_pt_regs();
	int ret;

	ret = exec_mmap();
	if (ret)
		return ret;

	start_thread(regs, (unsigned long)0xC0001000, (unsigned long)0xC0003000);

	/*
	 * This return will return to the point where do_execve()
	 * is invoked. The final return to user-space will happen
	 * when this kernel thread finishes and merges into
	 * the end of ret_from_fork().
	 *
	 * Check ret_from_fork() for more detail.
	 */
	return 0;
}

SYSCALL_DEFINE3(execve,
		const char *, filename,
		const char *const *, argv,
		const char *const *, envp)
{
	return do_execve(filename, argv, envp);
}

void __init exec_init(void)
{
	register_binfmt(&elf_format);
}
