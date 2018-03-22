/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Loader part is invoked only when memory-component receives execve()
 * SYSCALL request from processor-coponent. Loader will setup all vm related
 * data structures, and just return start_ip and start_sp back to processor.
 *
 * Loader also introduces another abstraction:
 *	Virtual Loader Layer:
 *	  |--> elf
 *	  |--> a.out
 *	  |--> script
 */

#include <lego/slab.h>
#include <lego/kernel.h>
#include <lego/string.h>
#include <lego/spinlock.h>

#include <memory/vm.h>
#include <memory/loader.h>
#include <memory/file_ops.h>
#include <memory/distvm.h>

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
				      struct lego_binprm *bprm,
				      u64 *new_ip, u64 *new_sp,
				      unsigned long *argv_len,
				      unsigned long *envp_len)
{
	int retval = -ENOENT;
	struct lego_binfmt *fmt;

	list_for_each_entry(fmt, &formats, lh) {
		retval = fmt->load_binary(tsk, bprm, new_ip, new_sp, argv_len, envp_len);
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

	bprm->vma = vma = kzalloc(sizeof(*vma), GFP_KERNEL);
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
	vma->vm_end = TASK_SIZE;
	vma->vm_start = vma->vm_end - PAGE_SIZE;
	vma->vm_flags = VM_STACK_FLAGS | VM_STACK_INCOMPLETE_SETUP;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

	err = insert_vm_struct(mm, vma);
	if (err)
		goto err;

	/* Temporary stack vma */
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
static int bprm_mm_init(struct lego_task_struct *tsk, struct lego_binprm *bprm
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
			,struct vmr_map_reply *reply
#endif
			)
{
	struct lego_mm_struct *mm = NULL;
	int err = -ENOMEM;

	bprm->mm = mm = lego_mm_alloc(tsk, NULL);
	if (!mm)
		goto err;

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	load_reply_buffer(mm, reply);
#endif

	err = __bprm_mm_init(bprm);
	if (err)
		goto err;

#ifdef CONFIG_DEBUG_LOADER
	pr_debug("****    Dump new mm:\n");
	dump_all_vmas_simple(bprm->mm);
	dump_all_vmas(bprm->mm);
	dump_lego_mm(bprm->mm);
	pr_debug("****    Finish dump new mm\n");
#endif

	return 0;

err:
	if (mm) {
		bprm->mm = NULL;
		lego_mmdrop(mm);
	}
	return err;
}

static int get_arg_page(struct lego_binprm *bprm,
			unsigned long start, unsigned long *kvaddr)
{
	struct vm_area_struct *vma;
	unsigned long flags;

	/*
	 * Note that:
	 * Use bprm->mm, this is the new temporary mm!
	 */
	vma = find_extend_vma(bprm->mm, start);
	if (!vma)
		return -EFAULT;

	/* We are going to copy strings, so make it a write fault */
	flags = FAULT_FLAG_WRITE;
	return faultin_page(vma, start, flags, kvaddr);
}

/*
 * Copy argument/environment strings to the temporary stack vma.
 * The source is kernel memory, the destination is user memory.
 * Thus we need to call faultin_page() to manually setup user pages.
 */
static int copy_strings(struct lego_task_struct *tsk, struct lego_binprm *bprm,
			u32 argc, const char **argv)
{
	int ret, len;
	unsigned long pos, kvaddr, kpos = 0;
	const char *str;

	while (argc-- > 0) {
		ret = -EINVAL;
		str = argv[argc];
		len = strnlen(str, MAX_ARG_STRLEN);
		if (!len)
			goto out;

		len++; /* terminator NULL */
		pos = bprm->p;
		str += len;
		bprm->p -= len;

		while (len > 0) {
			int offset, bytes_to_copy;

			offset = pos % PAGE_SIZE;
			if (offset == 0)
				offset = PAGE_SIZE;

			bytes_to_copy = offset;
			if (bytes_to_copy > len)
				bytes_to_copy = len;

			offset -= bytes_to_copy;
			pos -= bytes_to_copy;
			str -= bytes_to_copy;
			len -= bytes_to_copy;

			/* Do we need another page? */
			if (kpos != (pos & PAGE_MASK)) {
				ret = get_arg_page(bprm, pos, &kvaddr);
				if (ret)
					return ret;
				kpos = pos & PAGE_MASK;
			}
			strncpy((char *)(kvaddr + offset), str, bytes_to_copy);
		}
	}
	ret = 0;
out:
	return ret;
}

/**
 * exec_loader - loader binary formats
 *
 * Walk through registered binfmts interpreter until one recognizes.
 * Return 0 on success, others on failure.
 */
int exec_loader(struct lego_task_struct *tsk, const char *filename,
		u32 argc, const char **argv, unsigned long *argv_len,
		u32 envc, const char **envp, unsigned long *envp_len,
		u64 *new_ip, u64 *new_sp
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
		,struct vmr_map_reply *reply
#endif
	       )
{
	struct lego_binprm *bprm;
	struct lego_file *file;
	int retval;
	loff_t offset = 0;

	BUG_ON(!tsk || !filename || !argc || !argv || !envc || !envp);

	file = file_open(tsk, filename);
	if (IS_ERR(file)) {
		retval = PTR_ERR(file);
		goto out_ret;
	}

	bprm = kzalloc(sizeof(*bprm), GFP_KERNEL);
	if (!bprm) {
		retval = -ENOMEM;
		goto out_free_file;
	}

	bprm->argc = argc;
	bprm->envc = envc;
	bprm->file = file;

	/* Prepare a temporary stack vma */
	retval = bprm_mm_init(tsk, bprm
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
			  ,reply
#endif
			  );
	if (retval)
		goto out_free;

	/* Top of stack is filename */
	retval = copy_strings(tsk, bprm, 1, &filename);
	if (retval)
		goto out;

	/* Copy argv/envp to new process's stack */
	bprm->exec = bprm->p;
	retval = copy_strings(tsk, bprm, envc, envp);
	if (retval)
		goto out;

	retval = copy_strings(tsk, bprm, argc, argv);
	if (retval)
		goto out;

	/* Read the binary format header from the file */
	retval = file_read(tsk, bprm->file, bprm->buf, BINPRM_BUF_SIZE, &offset);
	if (WARN_ON(retval < 0))
		goto out;

	/*
	 * They will install the new mm and release the old mm,
	 * by calling flush_old_exec():
	 */
	retval = search_exec_binary_handler(tsk, bprm, new_ip, new_sp,
					    argv_len, envp_len);
	if (retval)
		goto out;

#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	remove_reply_buffer(tsk->mm);
#endif

	kfree(bprm);

#ifdef CONFIG_DEBUG_LOADER
	pr_debug("****    Dump final mm\n");
	dump_all_vmas_simple(tsk->mm);
	dump_all_vmas(tsk->mm);
	dump_lego_mm(tsk->mm);
	pr_debug("****    Finish dump final mm\n");
#endif
	return 0;

out:
	if (bprm->mm)
		lego_mmput(bprm->mm);
out_free:
	kfree(bprm);
out_free_file:
	file_close(file);
out_ret:
	return retval;
}

static int exec_mmap(struct lego_task_struct *tsk, struct lego_mm_struct *new_mm)
{
	struct lego_mm_struct *old_mm;

	old_mm = tsk->mm;
	BUG_ON(!old_mm);

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
}

/*
 * During bprm_mm_init(), we create a temporary stack at STACK_TOP_MAX.  Once
 * the binfmt code determines where the new stack should reside, we shift it to
 * its final location.  The process proceeds as follows:
 *
 * 1) Use shift to calculate the new vma endpoints.
 * 2) Extend vma to cover both the old and new ranges.  This ensures the
 *    arguments passed to subsequent functions are consistent.
 * 3) Move vma's page tables to the new range.
 * 4) Free up any cleared pgd range.
 * 5) Shrink the vma to cover only the new range.
 */
static int shift_arg_pages(struct vm_area_struct *vma, unsigned long shift)
{
	struct lego_mm_struct *mm = vma->vm_mm;
	unsigned long old_start = vma->vm_start;
	unsigned long old_end = vma->vm_end;
	unsigned long length = old_end - old_start;
	unsigned long new_start = old_start - shift;
	unsigned long new_end = old_end - shift;

	BUG_ON(new_start > new_end);

	/*
	 * ensure there are no vmas between where we want to go
	 * and where we are
	 */
	if (vma != find_vma(mm, new_start))
		return -EFAULT;

	/* cover the whole range: [new_start, old_end) */
	if (vma_adjust(vma, new_start, old_end, vma->vm_pgoff, NULL))
		return -ENOMEM;

	/*
	 * move the page tables downwards, on failure we rely on
	 * process cleanup to remove whatever mess we made.
	 */
	if (length != lego_move_page_tables(vma, old_start,
				       vma, new_start, length)) {
		WARN(1, "Fail to move lego pgtable!");
		return -ENOMEM;
	}

	if (new_end > old_start) {
		/*
		 * when the old and new regions overlap clear from new_end.
		 */
		lego_free_pgd_range(mm, new_end, old_end, new_end,
			vma->vm_next ? vma->vm_next->vm_start : USER_PGTABLES_CEILING);
	} else {
		/*
		 * otherwise, clean from old_start; this is done to not touch
		 * the address space in [new_end, old_start) some architectures
		 * have constraints on va-space that make this illegal (IA64) -
		 * for the others its just a little faster.
		 */
		lego_free_pgd_range(mm, old_start, old_end, new_end,
			vma->vm_next ? vma->vm_next->vm_start : USER_PGTABLES_CEILING);
	}

	/* Shrink the vma to just the new range.  Always succeeds. */
	vma_adjust(vma, new_start, new_end, vma->vm_pgoff, NULL);

	return 0;
}

/*
 * Finalizes the stack vm_area_struct. The flags and permissions are updated,
 * the stack is optionally relocated, and some extra space is added.
*/
int setup_arg_pages(struct lego_task_struct *tsk, struct lego_binprm *bprm,
		    unsigned long stack_top, int executable_stack)
{
	unsigned long ret;
	unsigned long stack_shift;
	struct lego_mm_struct *mm = tsk->mm;
	struct vm_area_struct *vma = bprm->vma;
	struct vm_area_struct *prev = NULL;
	unsigned long vm_flags;
	unsigned long stack_base;
	unsigned long stack_size;
	unsigned long stack_expand;

	stack_top = PAGE_ALIGN(stack_top);

	if (stack_top < sysctl_mmap_min_addr ||
	    vma->vm_end - vma->vm_start >= stack_top - sysctl_mmap_min_addr)
		return -ENOMEM;

	stack_shift = vma->vm_end - stack_top;
	bprm->p -= stack_shift;
	bprm->exec -= stack_shift;
	mm->arg_start = bprm->p;

	if (down_write_killable(&mm->mmap_sem))
		return -EINTR;

	vm_flags = VM_STACK_FLAGS;

	/*
	 * Adjust stack execute permissions; explicitly enable for
	 * EXSTACK_ENABLE_X, disable for EXSTACK_DISABLE_X and leave alone
	 * (arch default) otherwise.
	 */
	if (unlikely(executable_stack == EXSTACK_ENABLE_X))
		vm_flags |= VM_EXEC;
	else if (executable_stack == EXSTACK_DISABLE_X)
		vm_flags &= ~VM_EXEC;
	vm_flags |= mm->def_flags;
	vm_flags |= VM_STACK_INCOMPLETE_SETUP;

	ret = mprotect_fixup(tsk, vma, &prev, vma->vm_start, vma->vm_end,
			vm_flags);
	if (ret)
		goto out_unlock;
	BUG_ON(prev != vma);

	/* Move stack pages down in memory. */
	if (stack_shift) {
		ret = shift_arg_pages(vma, stack_shift);
		if (ret)
			goto out_unlock;
	}

	/* mprotect_fixup is overkill to remove the temporary stack flags */
	vma->vm_flags &= ~VM_STACK_INCOMPLETE_SETUP;

	stack_expand = 131072UL; /* randomly 32*4k (or 2*64k) pages */
	stack_size = vma->vm_end - vma->vm_start;
	stack_base = vma->vm_start - stack_expand;

	mm->start_stack = bprm->p;
	ret = expand_stack(vma, stack_base);
	if (ret)
		ret = -EFAULT;

out_unlock:
	up_write(&mm->mmap_sem);
	return ret;
}
