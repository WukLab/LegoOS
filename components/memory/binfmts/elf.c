/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/elf.h>
#include <lego/slab.h>
#include <lego/binfmts.h>
#include <lego/kernel.h>
#include <lego/string.h>
#include <lego/spinlock.h>

static int load_elf_binary(struct lego_task_struct *tsk,
			   struct lego_binprm *bprm)
{
	return 0;
}

struct lego_binfmt elf_format = {
	.load_binary	= load_elf_binary
};
