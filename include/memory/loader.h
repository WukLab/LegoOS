/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MEMORY_LOADER_H_
#define _LEGO_MEMORY_LOADER_H_

#include <lego/kernel.h>
#include <memory/task.h>

#ifdef CONFIG_DEBUG_LOADER
#define loader_debug(fmt, ...)	\
	pr_debug("%s(): " fmt "\n", __func__, __VA_ARGS__)
#else
static inline void loader_debug(const char *fmt, ...) { }
#endif

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

	unsigned long		exec;
	/* Current top of mem */
	unsigned long		p;
};

struct lego_binfmt {
	struct list_head lh;
	int (*load_binary)(struct lego_task_struct *, struct lego_binprm *,
			   u64 *new_ip, u64 *new_sp, unsigned long *, unsigned long *);
	int (*core_dump)(void);
};

/* Stack area protections */
#define EXSTACK_DEFAULT   0	/* Whatever the arch defaults to */
#define EXSTACK_DISABLE_X 1	/* Disable executable stacks */
#define EXSTACK_ENABLE_X  2	/* Enable executable stacks */

int flush_old_exec(struct lego_task_struct *tsk, struct lego_binprm *bprm);
void setup_new_exec(struct lego_task_struct *tsk, struct lego_binprm *bprm);
int setup_arg_pages(struct lego_task_struct *tsk, struct lego_binprm *bprm,
		    unsigned long stack_top, int executable_stack);

extern int exec_loader(struct lego_task_struct *tsk, const char *filename,
		       u32 argc, const char **argv, unsigned long *argv_len,
		       u32 envc, const char **envp, unsigned long *envp_len,
		       u64 *new_ip, u64 *new_sp
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
		      ,struct vmr_map_reply *reply
#endif
		       );

extern struct lego_binfmt elf_format;

void __init exec_init(void);

#endif /* _LEGO_MEMORY_LOADER_H_ */
