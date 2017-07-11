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

#include "internal.h"

/*
 * The least possible virtual address a process can map to:
 */
unsigned long sysctl_mmap_min_addr = PAGE_SIZE;

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

/**
 * exec_loader - loader binary formats
 *
 * Walk through registered binfmts interpreter until one recognizes.
 * Return 0 on success, others on failure.
 */
int exec_loader(struct lego_task_struct *tsk, const char *filename,
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

/*
 * TODO: signal
 * This function makes sure the current process has its own signal table,
 * so that flush_signal_handlers can later reset the handlers without
 * disturbing other processes.  (Other processes might share the signal
 * table via the CLONE_SIGHAND option to clone().)
 */
static int de_thread(struct lego_task_struct *tsk)
{
	return 0;
}

static int exec_mmap(struct lego_task_struct *tsk, struct lego_mm_struct *new_mm)
{
	struct lego_mm_struct *old_mm;

	old_mm = tsk->mm;
	lego_mm_release(tsk, old_mm);

	lego_task_lock(tsk);
	tsk->mm = new_mm;
	lego_task_unlock(tsk);

	/* dec mm_users */
	lego_mmput(old_mm);

	return 0;
}

/**
 * flush_old_exec
 *
 * Flush the old maping and release the lego_mm if needed
 * then install the new lego_mm into tsk.
 */
int flush_old_exec(struct lego_task_struct *tsk, struct lego_binprm *bprm)
{
	int retval;

	/*
	 * Make sure we have a private signal table and that
	 * we are unassociated from the previous thread group.
	 */
	retval = de_thread(tsk);
	if (retval)
		return retval;

	/*
	 * Release all of the old mmap stuff
	 * Activate new mm
	 */
	retval = exec_mmap(tsk, bprm->mm);
	if (retval)
		return retval;

	/* done with it, mark it as NULL */
	bprm->mm = NULL;

	return 0;
}

void setup_new_exec(struct lego_task_struct *tsk, struct lego_binprm *bprm)
{
	arch_pick_mmap_layout(tsk->mm);
	lego_set_task_comm(tsk, kbasename(bprm->file->filename));
	tsk->mm->task_size = TASK_SIZE;

	/*
	 * TODO: signal
	 */
}

/*
 * Finalizes the stack vm_area_struct. The flags and permissions are updated,
 * the stack is optionally relocated, and some extra space is added.
 */
int setup_arg_pages(struct lego_task_struct *tsk, struct lego_binprm *bprm,
		    unsigned long stack_top, int executable_stack)
{
	return 0;
}
