/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _MEMCOMPONENT_BINFMTS_INTERNAL_
#define _MEMCOMPONENT_BINFMTS_INTERNAL_

#include <lego/binfmts.h>
#include <lego/comp_memory.h>

extern struct lego_binfmt elf_format;

int flush_old_exec(struct lego_task_struct *tsk, struct lego_binprm *bprm);
void setup_new_exec(struct lego_task_struct *tsk, struct lego_binprm *bprm);

int setup_arg_pages(struct lego_task_struct *tsk, struct lego_binprm *bprm,
		    unsigned long stack_top, int executable_stack);

#endif /* _MEMCOMPONENT_BINFMTS_INTERNAL_ */
