/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "handle_execve: " fmt

#include <lego/slab.h>
#include <lego/binfmts.h>
#include <lego/kernel.h>
#include <lego/string.h>
#include <lego/fit_ibapi.h>
#include <lego/spinlock.h>
#include <lego/comp_common.h>
#include <lego/comp_memory.h>

static int load_elf_binary(struct lego_task_struct *tsk,
			   struct lego_binprm *bprm)
{
	return 0;
}

static struct lego_binfmt elf_format = {
	.load_binary	= load_elf_binary
};

static LIST_HEAD(formats);
static DEFINE_SPINLOCK(binfmt_lock);

static void __register_binfmt(struct lego_binfmt *fmt, int insert)
{
	BUG_ON(!fmt);
	if (WARN_ON(!fmt->load_binary))
		return;
	spin_lock(&binfmt_lock);
	insert ? list_add(&fmt->lh, &formats) :
		 list_add_tail(&fmt->lh, &formats);
	spin_unlock(&binfmt_lock);
}

/* Registration of default binfmt handlers */
static inline void register_binfmt(struct lego_binfmt *fmt)
{
	__register_binfmt(fmt, 0);
}

/**
 * exec_init
 * Register binary formats ONLY at memory-component
 */
void __init exec_init(void)
{
	register_binfmt(&elf_format);
}

/* Iterate the list of binary formats handler, until one recognizes the image */
static int search_exec_binary_handler(struct lego_task_struct *tsk,
				      struct lego_binprm *bprm)
{
	int retval = -ENOENT;
	struct lego_binfmt *fmt;

	list_for_each_entry(fmt, &formats, lh) {
		retval = fmt->load_binary(tsk, bprm);
		if (retval < 0 && !bprm->mm) {
			/*
			 * TODO:
			 * Send force_sigsegv(SIGSEGV);
			 */
			return retval;
		}
		if (retval != -ENOEXEC) {
			return retval;
		}
	}
	return retval;
}

static int __bprm_mm_init(struct lego_binprm *bprm)
{
	int err;
	struct vm_area_struct *vma = NULL;
	struct lego_mm_struct *mm = bprm->mm;

	bprm->vma = vma = kmalloc(sizeof(*vma), GFP_KERNEL);
	if (!vma)
		return -ENOMEM;

	vma->vm_mm = mm;

	/*
	 * Place the stack at the largest stack address the architecture
	 * supports. Later, we'll move this to an appropriate place. We don't
	 * use STACK_TOP because that can depend on attributes which aren't
	 * configured yet.
	 */
	BUILD_BUG_ON(VM_STACK_FLAGS & VM_STACK_INCOMPLETE_SETUP);
	vma->vm_end = STACK_TOP_MAX;
	vma->vm_start = vma->vm_end - PAGE_SIZE;
	vma->vm_flags = VM_STACK_FLAGS | VM_STACK_INCOMPLETE_SETUP;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
	INIT_LIST_HEAD(&vma->anon_vma_chain);

	err = insert_vm_struct(mm, vma);
	if (err)
		goto err;

	mm->stack_vm = mm->total_vm = 1;

	bprm->p = vma->vm_end - sizeof(void *);
	return 0;

err:
	if (vma) {
		bprm->vma = NULL;
		kfree(vma);
	}

	return err;
}

/*
 * Create a new lego_mm_struct and populate it with a temporary stack
 * vm_area_struct.  We don't have enough context at this point to set the stack
 * flags, permissions, and offset, so we use temporary values.  We'll update
 * them later in setup_arg_pages().
 */
static int bprm_mm_init(struct lego_task_struct *tsk, struct lego_binprm *bprm)
{
	struct lego_mm_struct *mm = NULL;
	int err = -ENOMEM;
	
	bprm->mm = mm = lego_mm_alloc(tsk);
	if (!mm)
		goto err;

	err = __bprm_mm_init(bprm);
	if (err)
		goto err;

	return 0;

err:
	if (mm) {
		bprm->mm = NULL;
		lego_mmdrop(mm);
	}
	return err;
}

static int exec_loader(struct lego_task_struct *tsk, const char *filename,
		       u32 argc, const char **argv,  u32 envc, const char **envp,
		       u64 *new_ip, u64 *new_sp)
{
	struct lego_binprm *bprm;
	struct lego_file *file;
	int retval;
	loff_t offset = 0;

	BUG_ON(!tsk || !filename || !argc || !argv || !envc || !envp);

	bprm = kzalloc(sizeof(*bprm), GFP_KERNEL);
	if (!bprm) {
		retval = -ENOMEM;
		goto out_ret;
	}

	bprm->argc = argc;
	bprm->envc = envc;
	bprm->file = file;

	retval = bprm_mm_init(tsk, bprm);
	if (retval)
		goto out_free;

	/* Read the binary format header from the file */
	retval = file_read(tsk, bprm->file, bprm->buf, BINPRM_BUF_SIZE, &offset);
	if (retval < 0)
		goto out;

	retval = search_exec_binary_handler(tsk, bprm);
	if (retval)
		goto out;

	kfree(bprm);
	return 0;

out:
	if (bprm->mm)
		lego_mmput(bprm->mm);
out_free:
	kfree(bprm);
out_ret:
	return retval;
}

int handle_p2m_execve(struct p2m_execve_struct *payload, u64 desc)
{
	struct m2p_execve_struct reply;
	__u32 argc, envc;
	const char **argv, **envp;
	const char *filename, *str;
	__u32 pid;
	struct lego_task_struct *tsk;
	int i, ret;
	__u64 new_ip, new_sp;

	pid = payload->pid;
	argc = payload->argc;
	envc = payload->envc;
	filename = payload->filename;

	pr_info("pid:%u,argc:%u,envc:%u,file:%s\n",
		pid, argc, envc, filename);

	argv = kzalloc(sizeof(*argv) * (argc + envc), GFP_KERNEL);
	if (!argv) {
		reply.status = RET_ENOMEM;
		goto out_reply;
	}

	/* Prepare argv and envp */
	str = (const char *)&(payload->array);
	for (i = 0; i < (argc + envc); i++) {
		argv[i] = str;
		str += strnlen(str, MAX_ARG_STRLEN);
		/* terminating NULL */
		str++;
	}
	envp = &argv[argc];

	/* Invoke real loader */
	ret = exec_loader(tsk, filename, argc, argv, envc, envp,
			  &new_ip, &new_sp);
	if (ret) {
		reply.status = RET_EPERM;
		goto out;
	}

	reply.status = RET_OKAY;
	reply.new_ip = new_ip;
	reply.new_sp = new_sp;

out:
	kfree(argv);
out_reply:
	ibapi_reply_message(&reply, sizeof(reply), desc);
	return 0;
}
