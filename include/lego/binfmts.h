/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_BINFMTS_H_
#define _LEGO_BINFMTS_H_

#include <lego/mm.h>
#include <lego/sched.h>
#include <lego/comp_memory.h>

int do_execve(const char *filename,
	      const char * const *argv,
	      const char * const *envp);

/*
 * These are the maximum length and maximum number of strings passed to the
 * execve() system call.  MAX_ARG_STRLEN is essentially random but serves to
 * prevent the kernel from being unduly impacted by misaddressed pointers.
 * MAX_ARG_STRINGS is chosen to fit in a signed 32-bit integer.
 */
#define MAX_ARG_STRLEN		(PAGE_SIZE * 32)
#define MAX_ARG_STRINGS		0x7FFFFFFF

/* sizeof(lego_binprm->buf) */
#define BINPRM_BUF_SIZE		128

/*
 * This structure is used to hold the arguments that are used when loading binaries.
 */
struct lego_binprm {
	char			buf[BINPRM_BUF_SIZE];
	struct lego_mm_struct	*mm;
	struct vm_area_struct	*vma;
	unsigned long		vma_pages;
	struct lego_file	*file;

	int			argc, envc;

	/* Current top of mem */
	unsigned long		p;
};

struct lego_binfmt {
	struct list_head lh;
	int (*load_binary)(struct lego_binprm *);
	int (*core_dump)(void);
};

#endif /* _LEGO_BINFMTS_H_ */
