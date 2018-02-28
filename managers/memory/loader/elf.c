/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * https://lwn.net/Articles/631631/
 * https://lwn.net/Articles/519085/
 * http://www.win.tue.nl/~aeb/linux/hh/stack-layout.html
 */

#include <lego/cred.h>
#include <lego/slab.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/auxvec.h>
#include <lego/jiffies.h>
#include <lego/random.h>
#include <lego/comp_memory.h>

#include <memory/vm.h>
#include <memory/elf.h>
#include <memory/loader.h>
#include <memory/file_ops.h>

#define ELF_MIN_ALIGN		PAGE_SIZE
#define ELF_CORE_EFLAGS		0
#define ELF_PAGESTART(_v)	((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v)	((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v)	(((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#define BAD_ADDR(x)	((unsigned long)(x) >= TASK_SIZE)

/*
 * We need to explicitly zero any fractional pages
 * after the data section (i.e. bss).  This would
 * contain the junk from the file that should not
 * be in memory
 */
static int padzero(struct lego_task_struct *tsk, unsigned long elf_bss)
{
	unsigned long nbyte;

	nbyte = ELF_PAGEOFFSET(elf_bss);
	if (nbyte) {
		nbyte = ELF_MIN_ALIGN - nbyte;
		loader_debug("[%#lx - %#lx]", elf_bss, elf_bss + nbyte - 1);
		if (lego_clear_user(tsk, (void *)elf_bss, nbyte))
			return -EFAULT;
	}
	return 0;
}

#define ELF_PLATFORM		("x86_64")
#define ELF_BASE_PLATFORM	NULL

#define STACK_ADD(sp, items)	((elf_addr_t __user *)(sp) - (items))
#define STACK_ROUND(sp, items)	(((unsigned long) (sp - items)) &~ 15UL)
#define STACK_ALLOC(sp, len)	({ sp -= len ; sp; })

/*
 * This function finalize the stack layout, put some machine specific info,
 * create the real argv[], envp[] pointer array, and finally the last thing
 * in the stack is argc.
 *
 * For a detailed stack layout, refer to:
 *	https://lwn.net/Articles/631631/
 *
 * More about auxv in:
 *	http://articles.manugarg.com/aboutelfauxiliaryvectors
 *
 * To see the contents of a progran, simply run:
 *	LD_SHOW_AUXV=1 ls
 */
static int create_elf_tables(struct lego_task_struct *tsk, struct lego_binprm *bprm,
		struct elfhdr *exec, unsigned long load_addr, unsigned long interp_load_addr,
		unsigned long *argv_len, unsigned long *envp_len)
{
	unsigned long zero = 0;
	unsigned long p = bprm->p;
	unsigned long argc = bprm->argc;
	unsigned long envc = bprm->envc;
	elf_addr_t __user *argv;
	elf_addr_t __user *envp;
	elf_addr_t __user *sp;
	elf_addr_t __user *u_platform;
	elf_addr_t __user *u_base_platform;
	elf_addr_t __user *u_rand_bytes;
	const char *k_platform = ELF_PLATFORM;
	const char *k_base_platform = ELF_BASE_PLATFORM;
	int items, i;
	elf_addr_t *elf_info;
	int ei_index = 0;
	struct vm_area_struct *vma;
	unsigned char k_rand_bytes[16];

	/*
	 * In some cases (e.g. Hyper-Threading), we want to avoid L1
	 * evictions by the processes running on the same package. One
	 * thing we can do is to shuffle the initial stack for them.
	 *
	 * XXX:
	 * Well. We do not have random things now.
	 */
	p &= ~0xf;

	/*
	 * If this architecture has a platform capability string, copy it
	 * to userspace.  In some cases (Sparc), this info is impossible
	 * for userspace to get any other way, in others (i386) it is
	 * merely difficult.
	 */
	u_platform = NULL;
	if (k_platform) {
		size_t len = strlen(k_platform) + 1;

		u_platform = (elf_addr_t __user *)STACK_ALLOC(p, len);
		if (!lego_copy_to_user(tsk, u_platform, k_platform, len))
			return -EFAULT;
	}

	/*
	 * If this architecture has a "base" platform capability
	 * string, copy it to userspace.
	 */
	u_base_platform = NULL;
	if (k_base_platform) {
		size_t len = strlen(k_base_platform) + 1;

		u_base_platform = (elf_addr_t __user *)STACK_ALLOC(p, len);
		if (!lego_copy_to_user(tsk, u_base_platform, k_base_platform, len))
			return -EFAULT;
	}

	/*
	 * Generate 16 random bytes for userspace PRND seeding
	 */
	get_random_bytes(k_rand_bytes, sizeof(k_rand_bytes));
	u_rand_bytes = (elf_addr_t __user *)
			STACK_ALLOC(p, sizeof(k_rand_bytes));
	if (!lego_copy_to_user(tsk, u_rand_bytes, k_rand_bytes, sizeof(k_rand_bytes)))
		return -EFAULT;

	/* Create the ELF interpreter info (auxvec) */
	ei_index = 0;
	elf_info = (elf_addr_t *)tsk->mm->saved_auxv;

	/* update AT_VECTOR_SIZE_BASE if the number of NEW_AUX_ENT() changes */
#define NEW_AUX_ENT(id, val) \
	do { \
		elf_info[ei_index++] = id; \
		elf_info[ei_index++] = val; \
	} while (0)

#ifdef ARCH_DLINFO
	/*
	 * ARCH_DLINFO must come first so PPC can do its special alignment of
	 * AUXV.
	 * update AT_VECTOR_SIZE_ARCH if the number of NEW_AUX_ENT() in
	 * ARCH_DLINFO changes
	 */
	ARCH_DLINFO;
#endif
	NEW_AUX_ENT(AT_HWCAP, ELF_HWCAP);
	NEW_AUX_ENT(AT_PAGESZ, ELF_EXEC_PAGESIZE);
	NEW_AUX_ENT(AT_CLKTCK, CLOCKS_PER_SEC);
	NEW_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
	NEW_AUX_ENT(AT_PHENT, sizeof(struct elf_phdr));
	NEW_AUX_ENT(AT_PHNUM, exec->e_phnum);
	NEW_AUX_ENT(AT_BASE, interp_load_addr);
	NEW_AUX_ENT(AT_FLAGS, 0);
	NEW_AUX_ENT(AT_ENTRY, exec->e_entry);
	NEW_AUX_ENT(AT_UID, current_uid());
	NEW_AUX_ENT(AT_EUID, current_euid());
	NEW_AUX_ENT(AT_GID, current_gid());
	NEW_AUX_ENT(AT_EGID, current_egid());
	NEW_AUX_ENT(AT_SECURE, 0);
	NEW_AUX_ENT(AT_RANDOM, (elf_addr_t)(unsigned long)u_rand_bytes);
#ifdef ELF_HWCAP2
	NEW_AUX_ENT(AT_HWCAP2, ELF_HWCAP2);
#endif
	NEW_AUX_ENT(AT_EXECFN, bprm->exec);
	if (k_platform) {
		NEW_AUX_ENT(AT_PLATFORM,
			    (elf_addr_t)(unsigned long)u_platform);
	}
	if (k_base_platform) {
		NEW_AUX_ENT(AT_BASE_PLATFORM,
			    (elf_addr_t)(unsigned long)u_base_platform);
	}
#undef NEW_AUX_ENT
	/* AT_NULL is zero; clear the rest too */
	memset(&elf_info[ei_index], 0,
	       sizeof tsk->mm->saved_auxv - ei_index * sizeof elf_info[0]);

	/* And advance past the AT_NULL entry.  */
	ei_index += 2;

	sp = STACK_ADD(p, ei_index);

	/*
	 * 1) nr of envc pointers
	 * 2) NULL
	 * 3) nr of argc pointers
	 * 4) argc variable
	 */
	items = (argc + 1) + (envc + 1) + 1;
	bprm->p = STACK_ROUND(sp, items);
	sp = (elf_addr_t __user *)bprm->p;

	/*
	 * Grow the stack manually; some architectures have a limit on how
	 * far ahead a user-space access may be in order to grow the stack.
	 */
	vma = find_extend_vma(tsk->mm, bprm->p);
	if (WARN_ON(!vma))
		return -EFAULT;

	/*
	 * Now, let's put argc (and argv, envp if appropriate)
	 * on the stack backward (sp is calculated above)
	 */
	if (!lego_copy_to_user(tsk, sp, &argc, sizeof(*sp)))
		return -EFAULT;
	sp++;
	argv = sp;
	envp = argv + argc + 1;

	/* Populate argv */
	p = tsk->mm->arg_end = tsk->mm->arg_start;
	for (i = 0; i < argc; i++) {
		if (!lego_copy_to_user(tsk, argv++, &p, sizeof(*argv)))
			return -EFAULT;
		p += argv_len[i];
	}

	/* final 0 */
	if (!lego_copy_to_user(tsk, argv, &zero, sizeof(*argv)))
		return -EFAULT;

	/* Populate envp */
	tsk->mm->arg_end = tsk->mm->env_start = p;
	for (i = 0; i < envc; i++) {
		if (!lego_copy_to_user(tsk, envp++, &p, sizeof(*envp)))
			return -EFAULT;
		p += envp_len[i];
	}

	/* final 0 */
	if (!lego_copy_to_user(tsk, envp, &zero, sizeof(*envp)))
		return -EFAULT;

	tsk->mm->env_end = p;

	/* Put the elf_info on the stack in the right place.  */
	sp = (elf_addr_t __user *)envp + 1;
	if (!lego_copy_to_user(tsk, sp, elf_info, ei_index * sizeof(elf_addr_t)))
		return -EFAULT;

	return 0;
}

static unsigned long elf_map(struct lego_task_struct *tsk, struct lego_file *filep,
		unsigned long addr, struct elf_phdr *eppnt, int prot, int type,
		unsigned long total_size)
{
	unsigned long map_addr;
	unsigned long size = eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr);
	unsigned long off = eppnt->p_offset - ELF_PAGEOFFSET(eppnt->p_vaddr);
	addr = ELF_PAGESTART(addr);
	size = ELF_PAGEALIGN(size);

	loader_debug("f:%s, addr: %#lx, size: %#lx type: %d total_size: %#lx (caller: %pS)",
		filep->filename, addr, size, type, total_size, __builtin_return_address(0));

	/* mmap() will return -EINVAL if given a zero size, but a
	 * segment with zero filesize is perfectly valid */
	if (!size)
		return addr;

	/*
	 * total_size is the size of the ELF (interpreter) image.
	 * The _first_ mmap needs to know the full size, otherwise
	 * randomization might put this image into an overlapping
	 * position with the ELF binary image. (since size < total_size)
 	 * So we first map the 'big' image - and unmap the remainder at
	 * the end. (which unmap is needed for ELF images with holes.)
	 */
	if (total_size) {
		total_size = ELF_PAGEALIGN(total_size);
		map_addr = vm_mmap(tsk, filep, addr, total_size, prot, type, off);
		if (!BAD_ADDR(map_addr))
			vm_munmap(tsk, map_addr+size, total_size-size);
	} else
		map_addr = vm_mmap(tsk, filep, addr, size, prot, type, off);

	return(map_addr);
}

static int set_brk(struct lego_task_struct *tsk,
		   unsigned long start, unsigned long end)
{
	start = ELF_PAGEALIGN(start);
	end = ELF_PAGEALIGN(end);

	loader_debug("[%#lx - %#lx]", start, end);
	if (end > start) {
		int error;

		error = vm_brk(tsk, start, end - start);
		if (error)
			return error;
	}
	tsk->mm->start_brk = tsk->mm->brk = end;
	return 0;
}

static unsigned long total_mapping_size(struct elf_phdr *cmds, int nr)
{
	int i, first_idx = -1, last_idx = -1;

	for (i = 0; i < nr; i++) {
		if (cmds[i].p_type == PT_LOAD) {
			last_idx = i;
			if (first_idx == -1)
				first_idx = i;
		}
	}
	if (first_idx == -1)
		return 0;

	return cmds[last_idx].p_vaddr + cmds[last_idx].p_memsz -
				ELF_PAGESTART(cmds[first_idx].p_vaddr);
}

/**
 * load_elf_phdrs() - load ELF program headers
 * @tsk:      lego task struct
 * @elf_ex:   ELF header of the binary whose program headers should be loaded
 * @elf_file: ELF binary file
 *
 * Loads ELF program headers from the binary file elf_file, which has the ELF
 * header pointed to by elf_ex, into a newly allocated array. The caller is
 * responsible for freeing the allocated data. Returns an ERR_PTR upon failure.
 */
static struct elf_phdr *load_elf_phdrs(struct lego_task_struct *tsk,
			struct elfhdr *elf_ex, struct lego_file *elf_file)
{
	struct elf_phdr *elf_phdata = NULL;
	int retval, size, err = -1;
	loff_t pos;

	/*
	 * If the size of this structure has changed, then punt, since
	 * we will be doing the wrong thing.
	 */
	if (elf_ex->e_phentsize != sizeof(struct elf_phdr))
		goto out;

	/* Sanity check the number of program headers... */
	if (elf_ex->e_phnum < 1 ||
		elf_ex->e_phnum > 65536U / sizeof(struct elf_phdr))
		goto out;

	/* ...and their total size. */
	size = sizeof(struct elf_phdr) * elf_ex->e_phnum;
	if (size > ELF_MIN_ALIGN)
		goto out;

	elf_phdata = kmalloc(size, GFP_KERNEL);
	if (!elf_phdata)
		goto out;

	/* Read in the program headers */
	pos = elf_ex->e_phoff;
	retval= file_read(tsk, elf_file, (char *)elf_phdata, size, &pos);
	if (retval != size) {
		err = (retval < 0) ? retval : -EIO;
		goto out;
	}

	/* Success! */
	err = 0;
out:
	if (err) {
		kfree(elf_phdata);
		elf_phdata = NULL;
	}
	return elf_phdata;
}

/* This is much more generalized than the library routine read function,
   so we keep this separate.  Technically the library read function
   is only provided so that we can read a.out libraries that have
   an ELF header */

static unsigned long load_elf_interp(struct lego_task_struct *tsk,
		struct elfhdr *interp_elf_ex,
		struct lego_file *interpreter, unsigned long *interp_map_addr,
		unsigned long no_base, struct elf_phdr *interp_elf_phdata)
{
	struct elf_phdr *eppnt;
	unsigned long load_addr = 0;
	int load_addr_set = 0;
	unsigned long last_bss = 0, elf_bss = 0;
	unsigned long error = ~0UL;
	unsigned long total_size;
	int i;

	/* First of all, some simple consistency checks */
	if (interp_elf_ex->e_type != ET_EXEC &&
	    interp_elf_ex->e_type != ET_DYN)
		goto out;
	if (!elf_check_arch(interp_elf_ex))
		goto out;
	BUG_ON(!interpreter->f_op->mmap);

	total_size = total_mapping_size(interp_elf_phdata,
					interp_elf_ex->e_phnum);
	if (!total_size) {
		error = -EINVAL;
		goto out;
	}

	eppnt = interp_elf_phdata;
	for (i = 0; i < interp_elf_ex->e_phnum; i++, eppnt++) {
		if (eppnt->p_type == PT_LOAD) {
			int elf_type = MAP_PRIVATE | MAP_DENYWRITE;
			int elf_prot = 0;
			unsigned long vaddr = 0;
			unsigned long k, map_addr;

			if (eppnt->p_flags & PF_R)
		    		elf_prot = PROT_READ;
			if (eppnt->p_flags & PF_W)
				elf_prot |= PROT_WRITE;
			if (eppnt->p_flags & PF_X)
				elf_prot |= PROT_EXEC;
			vaddr = eppnt->p_vaddr;
			if (interp_elf_ex->e_type == ET_EXEC || load_addr_set)
				elf_type |= MAP_FIXED;
			else if (no_base && interp_elf_ex->e_type == ET_DYN)
				load_addr = -vaddr;

			map_addr = elf_map(tsk, interpreter, load_addr + vaddr,
					eppnt, elf_prot, elf_type, total_size);
			total_size = 0;
			if (!*interp_map_addr)
				*interp_map_addr = map_addr;
			error = map_addr;
			if (BAD_ADDR(map_addr))
				goto out;

			if (!load_addr_set &&
			    interp_elf_ex->e_type == ET_DYN) {
				load_addr = map_addr - ELF_PAGESTART(vaddr);
				load_addr_set = 1;
			}

			/*
			 * Check to see if the section's size will overflow the
			 * allowed task size. Note that p_filesz must always be
			 * <= p_memsize so it's only necessary to check p_memsz.
			 */
			k = load_addr + eppnt->p_vaddr;
			if (BAD_ADDR(k) ||
			    eppnt->p_filesz > eppnt->p_memsz ||
			    eppnt->p_memsz > TASK_SIZE ||
			    TASK_SIZE - eppnt->p_memsz < k) {
				error = -ENOMEM;
				goto out;
			}

			/*
			 * Find the end of the file mapping for this phdr, and
			 * keep track of the largest address we see for this.
			 */
			k = load_addr + eppnt->p_vaddr + eppnt->p_filesz;
			if (k > elf_bss)
				elf_bss = k;

			/*
			 * Do the same thing for the memory mapping - between
			 * elf_bss and last_bss is the bss section.
			 */
			k = load_addr + eppnt->p_vaddr + eppnt->p_memsz;
			if (k > last_bss)
				last_bss = k;
		}
	}

	/*
	 * Now fill out the bss section: first pad the last page from
	 * the file up to the page boundary, and zero it from elf_bss
	 * up to the end of the page.
	 */
	if (padzero(tsk, elf_bss)) {
		error = -EFAULT;
		goto out;
	}
	/*
	 * Next, align both the file and mem bss up to the page size,
	 * since this is where elf_bss was just zeroed up to, and where
	 * last_bss will end after the vm_brk() below.
	 */
	elf_bss = ELF_PAGEALIGN(elf_bss);
	last_bss = ELF_PAGEALIGN(last_bss);
	/* Finally, if there is still more bss to allocate, do it. */
	if (last_bss > elf_bss) {
		error = vm_brk(tsk, elf_bss, last_bss - elf_bss);
		if (error)
			goto out;
	}

	error = load_addr;
out:
	return error;
}

static int load_elf_binary(struct lego_task_struct *tsk, struct lego_binprm *bprm,
			   u64 *new_ip, u64 *new_sp, unsigned long *argv_len, unsigned long *envp_len)
{
	struct lego_file *interpreter = NULL;
	char *elf_interpreter = NULL;
 	unsigned long load_addr = 0, load_bias = 0;
	int load_addr_set = 0;
	unsigned long error;
	struct elf_phdr *elf_ppnt, *elf_phdata, *interp_elf_phdata = NULL;
	int retval, i;
	unsigned long elf_entry;	/* program entry point */
	unsigned long elf_bss;		/* start of bss */
	unsigned long elf_brk;		/* start of brk */
	unsigned long interp_load_addr = 0;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long reloc_func_desc __maybe_unused = 0;
	int executable_stack = EXSTACK_DEFAULT;
	struct lego_mm_struct *mm;
	struct {
		struct elfhdr elf_ex;
		struct elfhdr interp_elf_ex;
	} *loc;

	BUG_ON(!tsk || !bprm->file);

	loc = kmalloc(sizeof(*loc), GFP_KERNEL);
	if (!loc) {
		retval = -ENOMEM;
		goto out_ret;
	}

	/* Get the exec-header */
	loc->elf_ex = *((struct elfhdr *)bprm->buf);

	retval = -ENOEXEC;
	/* First of all, some simple consistency checks */
	if (memcmp(loc->elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
		goto out;

	/*
	 * Lego only supportes executables.
	 * (Both dynamic/static linked executables are ET_EXEC)
	 * No relocatable object file (ET_REL)
	 * -----No shared library (ET_DYN) ----
	 *  02.27.18 We now support
	 */
	if (loc->elf_ex.e_type != ET_EXEC && loc->elf_ex.e_type != ET_DYN)
		goto out;

	if (!elf_check_arch(&loc->elf_ex))
		goto out;

	elf_phdata = load_elf_phdrs(tsk, &loc->elf_ex, bprm->file);
	if (!elf_phdata)
		goto out;

	elf_ppnt = elf_phdata;
	elf_bss = 0;
	elf_brk = 0;

	start_code = ~0UL;
	end_code = 0;
	start_data = 0;
	end_data = 0;

	for (i = 0; i < loc->elf_ex.e_phnum; i++) {
		if (elf_ppnt->p_type == PT_INTERP) {
#ifdef CONFIG_USE_RAMFS
			panic("Using dynamically-linked ELF requires storage node.");
#endif

			/*
			 * This is the program interpreter used for
			 * shared libraries - for now assume that this
			 * is an a.out format binary
			 */
			retval = -ENOEXEC;
			if (elf_ppnt->p_filesz > PATH_MAX || 
			    elf_ppnt->p_filesz < 2)
				goto out_free_ph;

			retval = -ENOMEM;
			elf_interpreter = kmalloc(elf_ppnt->p_filesz,
						  GFP_KERNEL);
			if (!elf_interpreter)
				goto out_free_ph;

			/* Get ELF interpreter file name */
			retval = kernel_read(tsk, bprm->file, elf_ppnt->p_offset,
					     elf_interpreter,
					     elf_ppnt->p_filesz);
			if (retval != elf_ppnt->p_filesz) {
				WARN_ON(1);
				if (retval >= 0)
					retval = -EIO;
				goto out_free_interp;
			}

			/* make sure path is NULL terminated */
			retval = -ENOEXEC;
			if (elf_interpreter[elf_ppnt->p_filesz - 1] != '\0')
				goto out_free_interp;

			loader_debug("elf_interpreter: %s", elf_interpreter);

			interpreter = file_open(tsk, elf_interpreter);
			retval = PTR_ERR(interpreter);
			if (IS_ERR(interpreter))
				goto out_free_interp;

			/* Get the exec headers */
			retval = kernel_read(tsk, interpreter, 0,
					     (void *)&loc->interp_elf_ex,
					     sizeof(loc->interp_elf_ex));
			if (retval != sizeof(loc->interp_elf_ex)) {
				WARN_ON(1);
				if (retval >= 0)
					retval = -EIO;
				goto out_free_dentry;
			}

			break;
		}
		elf_ppnt++;
	}

	elf_ppnt = elf_phdata;
	for (i = 0; i < loc->elf_ex.e_phnum; i++, elf_ppnt++) {
		switch (elf_ppnt->p_type) {
		case PT_GNU_STACK:
			if (elf_ppnt->p_flags & PF_X)
				executable_stack = EXSTACK_ENABLE_X;
			else
				executable_stack = EXSTACK_DISABLE_X;
			break;
		}
	}

	/* Some simple consistency checks for the interpreter */
	if (elf_interpreter) {
		retval = -ELIBBAD;
		/* Not an ELF interpreter */
		if (memcmp(loc->interp_elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
			goto out_free_dentry;
		/* Verify the interpreter has a valid arch */
		if (!elf_check_arch(&loc->interp_elf_ex))
			goto out_free_dentry;

		/* Load the interpreter program headers */
		interp_elf_phdata = load_elf_phdrs(tsk, &loc->interp_elf_ex,
						   interpreter);
		if (!interp_elf_phdata)
			goto out_free_dentry;
	}

	/*
	 * Flush and release old lego_mm_struct
	 * and install new lego_mm into tsk:
	 */
	retval = flush_old_exec(tsk, bprm);
	if (retval)
		goto out_free_ph;

	/* setup basic mmap info */
	setup_new_exec(tsk, bprm);

	/*
	 * Do this so that we can load the interpreter.
	 *
	 * Adjust previously allocated temporary stack vma
	 * shift everything down if needed:
	 */
	retval = setup_arg_pages(tsk, bprm, TASK_SIZE, executable_stack);
	if (retval < 0)
		goto out_free_ph;

	tsk->mm->start_stack = bprm->p;

	/*
	 * Now we do a little grungy work by mmapping the ELF image into
	 * the correct location in memory.
	 */
	elf_ppnt = elf_phdata;
	for (i = 0; i < loc->elf_ex.e_phnum; i++, elf_ppnt++) {
		int elf_prot = 0, elf_flags;
		unsigned long k, vaddr;
		unsigned long total_size = 0;

		if (elf_ppnt->p_type != PT_LOAD)
			continue;

		if (unlikely(elf_brk > elf_bss)) {
			unsigned long nbyte;

			/*
			 * There was a PT_LOAD segment with p_memsz > p_filesz
			 * before this one. Map anonymous pages, if needed,
			 * and clear the area.
			 *
			 * Normally, the segment that has the .bss section
			 * comes at last, so, unlikely.
			 */
			retval = set_brk(tsk, elf_bss + load_bias,
					      elf_brk + load_bias);
			if (retval)
				goto out_free_ph;
			nbyte = ELF_PAGEOFFSET(elf_bss);
			if (nbyte) {
				nbyte = ELF_MIN_ALIGN - nbyte;
				if (nbyte > elf_brk - elf_bss)
					nbyte = elf_brk - elf_bss;
				if (lego_clear_user(tsk,
					(void *)elf_bss + load_bias, nbyte)) {
					/*
					 * This bss-zeroing can fail if the ELF
					 * file specifies odd protections. So
					 * we don't check the return value
					 */
				}
			}
		}

		if (elf_ppnt->p_flags & PF_R)
			elf_prot |= PROT_READ;
		if (elf_ppnt->p_flags & PF_W)
			elf_prot |= PROT_WRITE;
		if (elf_ppnt->p_flags & PF_X)
			elf_prot |= PROT_EXEC;

		elf_flags = MAP_PRIVATE | MAP_DENYWRITE | MAP_EXECUTABLE;

		vaddr = elf_ppnt->p_vaddr;
		/*
		 * If we are loading ET_EXEC or we have already performed
		 * the ET_DYN load_addr calculations, proceed normally.
		 */
		if (loc->elf_ex.e_type == ET_EXEC || load_addr_set) {
			elf_flags |= MAP_FIXED;
		} else if (loc->elf_ex.e_type == ET_DYN) {
			/*
			 * This logic is run once for the first LOAD Program
			 * Header for ET_DYN binaries to calculate the
			 * randomization (load_bias) for all the LOAD
			 * Program Headers, and to calculate the entire
			 * size of the ELF mapping (total_size). (Note that
			 * load_addr_set is set to true later once the
			 * initial mapping is performed.)
			 *
			 * There are effectively two types of ET_DYN
			 * binaries: programs (i.e. PIE: ET_DYN with INTERP)
			 * and loaders (ET_DYN without INTERP, since they
			 * _are_ the ELF interpreter). The loaders must
			 * be loaded away from programs since the program
			 * may otherwise collide with the loader (especially
			 * for ET_EXEC which does not have a randomized
			 * position). For example to handle invocations of
			 * "./ld.so someprog" to test out a new version of
			 * the loader, the subsequent program that the
			 * loader loads must avoid the loader itself, so
			 * they cannot share the same load range. Sufficient
			 * room for the brk must be allocated with the
			 * loader as well, since brk must be available with
			 * the loader.
			 *
			 * Therefore, programs are loaded offset from
			 * ELF_ET_DYN_BASE and loaders are loaded into the
			 * independently randomized mmap region (0 load_bias
			 * without MAP_FIXED).
			 */

			loader_debug("ET_DYN: shared object file. (%s)", elf_interpreter);
			if (elf_interpreter) {
				load_bias = ELF_ET_DYN_BASE;
				elf_flags |= MAP_FIXED;
			} else
				load_bias = 0;

			/*
			 * Since load_bias is used for all subsequent loading
			 * calculations, we must lower it by the first vaddr
			 * so that the remaining calculations based on the
			 * ELF vaddrs will be correctly offset. The result
			 * is then page aligned.
			 */
			load_bias = ELF_PAGESTART(load_bias - vaddr);

			total_size = total_mapping_size(elf_phdata,
							loc->elf_ex.e_phnum);
			if (!total_size) {
				retval = -EINVAL;
				goto out_free_dentry;
			}
		}

		error = elf_map(tsk, bprm->file, load_bias + vaddr, elf_ppnt,
				elf_prot, elf_flags, total_size);
		if (BAD_ADDR(error)) {
			WARN_ON(1);
			retval = IS_ERR((void *)error) ?
				PTR_ERR((void*)error) : -EINVAL;
			goto out_free_ph;
		}

		if (!load_addr_set) {
			load_addr_set = 1;
			load_addr = (elf_ppnt->p_vaddr - elf_ppnt->p_offset);
			if (loc->elf_ex.e_type == ET_DYN) {
				load_bias += error -
				             ELF_PAGESTART(load_bias + vaddr);
				load_addr += load_bias;
				reloc_func_desc = load_bias;
			}
		}

		k = elf_ppnt->p_vaddr;
		if (k < start_code)
			start_code = k;
		if (start_data < k)
			start_data = k;

		/*
		 * Check to see if the section's size will overflow the
		 * allowed task size. Note that p_filesz must always be
		 * <= p_memsz so it is only necessary to check p_memsz.
		 */
		if (BAD_ADDR(k) || elf_ppnt->p_filesz > elf_ppnt->p_memsz ||
		    elf_ppnt->p_memsz > TASK_SIZE ||
		    TASK_SIZE - elf_ppnt->p_memsz < k) {
			/* set_brk can never work. Avoid overflows. */
			retval = -EINVAL;
			goto out_free_ph;
		}

		k = elf_ppnt->p_vaddr + elf_ppnt->p_filesz;
		if (k > elf_bss)
			elf_bss = k;
		if ((elf_ppnt->p_flags & PF_X) && end_code < k)
			end_code = k;
		if (end_data < k)
			end_data = k;

		k = elf_ppnt->p_vaddr + elf_ppnt->p_memsz;
		if (k > elf_brk)
			elf_brk = k;
	}

	loc->elf_ex.e_entry += load_bias;
	elf_bss += load_bias;
	elf_brk += load_bias;
	start_code += load_bias;
	end_code += load_bias;
	start_data += load_bias;
	end_data += load_bias;

	loader_debug("code: [%#lx-%#lx] data: [%#lx-%#lx] "
		     "elf_bss: %#lx, elf_brk: %#lx",
		     start_code, end_code, start_data, end_data,
		     elf_bss, elf_brk);

	/*
	 * Calling set_brk effectively mmaps the pages
	 * that we need for the bss and break sections.
	 *
	 * .bss and brk are combined together!
	 */
	retval = set_brk(tsk, elf_bss, elf_brk);
	if (retval)
		goto out_free_ph;

	/*
	 * Clear the fontend of .bss that
	 * may share the same page with .data
	 */
	if (likely(elf_bss != elf_brk) && unlikely(padzero(tsk, elf_bss))) {
		retval = -EFAULT; /* Nobody gets to see this, but.. */
		goto out_free_ph;
	}

	if (elf_interpreter) {
		unsigned long interp_map_addr = 0;

		elf_entry = load_elf_interp(tsk, &loc->interp_elf_ex,
					    interpreter,
					    &interp_map_addr,
					    load_bias, interp_elf_phdata);
		if (!IS_ERR((void *)elf_entry)) {
			/*
			 * load_elf_interp() returns relocation
			 * adjustment
			 */
			interp_load_addr = elf_entry;
			elf_entry += loc->interp_elf_ex.e_entry;
		}
		if (BAD_ADDR(elf_entry)) {
			retval = IS_ERR((void *)elf_entry) ?
					(int)elf_entry : -EINVAL;
			goto out_free_dentry;
		}
		reloc_func_desc = interp_load_addr;

		put_lego_file(interpreter);
		kfree(elf_interpreter);
	} else {
		/*
		 * e_entry is the VA to which the system first transfers control
		 * Not the start_code! Normally, it is the <_start> function.
		 */
		elf_entry = loc->elf_ex.e_entry;
		if (BAD_ADDR(elf_entry)) {
			retval = -EINVAL;
			goto out_free_dentry;
		}
	}

	if (interp_elf_phdata)
		kfree(interp_elf_phdata);
	kfree(elf_phdata);

#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
	/*
	 * TODO: vdso
	 * x86 can map vdso vma here
	 */
#endif

	retval = create_elf_tables(tsk, bprm, &loc->elf_ex,
			  load_addr, interp_load_addr, argv_len, envp_len);
	if (retval < 0)
		goto out;

	mm = tsk->mm;
	mm->end_code = end_code;
	mm->start_code = start_code;
	mm->start_data = start_data;
	mm->end_data = end_data;
	mm->start_stack = bprm->p;
	mm->start_bss = elf_bss;

	/*
	 * e_entry is the VA to which the system first transfers control
	 * Not the start_code! Normally, it is the <_start> function.
	 */
	*new_ip = elf_entry;
	*new_sp = mm->start_stack;

	/* finally, huh? */
	retval = 0;
out:
	kfree(loc);
out_ret:
	return retval;

	/* error cleanup */
out_free_dentry:
	kfree(interp_elf_phdata);
	if (interpreter)
		put_lego_file(interpreter);
out_free_interp:
	kfree(elf_interpreter);
out_free_ph:
	kfree(elf_phdata);
	goto out;
}

struct lego_binfmt elf_format = {
	.load_binary	= load_elf_binary
};
