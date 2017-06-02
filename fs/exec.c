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

int do_execve(const char *filename,
	      const char * const *argv,
	      const char * const *envp)
{
	struct pt_regs *regs = current_pt_regs();

	start_thread(regs, (unsigned long)0xC0001000, (unsigned long)0xC0002000);

	/* Return to the newly replaced program */
	return 0;
}

void __init exec_init(void)
{
	register_binfmt(&elf_format);
}
