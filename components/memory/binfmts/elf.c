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
#include <lego/sched.h>
#include <lego/binfmts.h>
#include <lego/kernel.h>
#include <lego/comp_memory.h>

#define ELF_EXEC_PAGESIZE	4096

#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN	ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN	PAGE_SIZE
#endif

#ifndef ELF_CORE_EFLAGS
#define ELF_CORE_EFLAGS		0
#endif

#define ELF_PAGESTART(_v) 	((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) 	((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) 	(((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#define BAD_ADDR(x) ((unsigned long)(x) >= TASK_SIZE)

static unsigned long randomize_stack_top(unsigned long stack_top)
{
	/* Stack randomization omitted */
	return stack_top;
}

static int set_brk(struct lego_task_struct *proc, unsigned long start, unsigned long end)
{
	start = ELF_PAGEALIGN(start);
	end = ELF_PAGEALIGN(end);
	if (end > start) {
		int error = vm_brk(proc, start, end - start);
		if (error)
			return error;
	}
	proc->mm->start_brk = proc->mm->brk = end;
	return 0;
}

// used to initialize the bss section data to zero 
int clear_user(void *addr, unsigned long size)
{
	/* The clear_user function is used to zero a block of memory in user space. */
	return 0;
}

static int padzero(unsigned long elf_bss)
{
	unsigned long nbyte;

	nbyte = ELF_PAGEOFFSET(elf_bss);
	if (nbyte) {
		nbyte = ELF_MIN_ALIGN - nbyte;
		if (clear_user((void *)elf_bss, nbyte))
			return -EFAULT;
	}
	return 0;
}

static int create_elf_tables(struct lego_binprm *bprm, struct elfhdr *exec,
		unsigned long load_addr, unsigned long interp_load_addr)
{
/* This allocates user mode pages for this process and copies the argv and 
 * environment variables to those allocated page addresses. Finally argc, 
 * the argv pointer and the environment variable array pointer are pushed 
 * to user mode stack by create_elf_tables() 
 */
	return 0;
}


static unsigned long elf_map(struct lego_task_struct *proc, struct lego_file *filep, unsigned long addr,
		struct elf_phdr *eppnt, int prot, int type,
		unsigned long total_size)
{                                                                      
	unsigned long map_addr;
	unsigned long size = eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr);
	unsigned long off = eppnt->p_offset - ELF_PAGEOFFSET(eppnt->p_vaddr);
	addr = ELF_PAGESTART(addr);
	size = ELF_PAGEALIGN(size);

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
		map_addr = vm_mmap(proc, filep, addr, total_size, prot, type, off);
		if (!BAD_ADDR(map_addr))
			vm_munmap(proc, map_addr+size, total_size-size);
	} else
		map_addr = vm_mmap(proc, filep, addr, size, prot, type, off);

	return(map_addr);
}

/**
 *  load_elf_phdrs() - load ELF program headers
 *  @elf_ex:   ELF header of the binary whose program headers should be loaded
 *  @elf_file: ELF binary file
 *
 * Loads ELF program headers from the binary file elf_file, which has the ELF
 * header pointed to by elf_ex, into a newly allocated array. The caller is
 * responsible for freeing the allocated data. Returns an ERR_PTR upon failure.
 */
static struct elf_phdr *load_elf_phdrs(struct elfhdr *elf_ex, struct lego_file *elf_file)
{
	struct elf_phdr *elf_phdata = NULL;
	int retval, size, err = -1;

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
	//retval = file_read(elf_file, elf_ex->e_phoff, (char *)elf_phdata, size);
	
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

static int load_elf_binary(struct lego_task_struct *p, struct lego_binprm *bprm)
{
 	unsigned long load_addr = 0, load_bias = 0;
	int load_addr_set = 0;
	char * elf_interpreter = NULL;
	unsigned long error;
	struct elf_phdr *elf_ppnt, *elf_phdata;
	unsigned long elf_bss, elf_brk;
	int retval, i;
	unsigned long elf_entry;
	unsigned long interp_load_addr = 0;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long reloc_func_desc __maybe_unused = 0;
	int executable_stack = EXSTACK_DEFAULT;
	struct lego_mm_struct *mm = NULL;
	
	struct {
		struct elfhdr elf_ex;
		struct elfhdr interp_elf_ex;
	} *loc;

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
	if (loc->elf_ex.e_type != ET_EXEC)
		goto out;
	/* Shared object file not supported */
	if (!elf_check_arch(&loc->elf_ex))
		goto out;
	if (!bprm->file)
		goto out; // mmap() check through func pointer?

	elf_phdata = load_elf_phdrs(&loc->elf_ex, bprm->file);
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
			/* This is the program interpreter used for
			 * shared libraries - not supported for now
			 */
			retval = -ENOEXEC;
			goto out_free_ph;
		}
		elf_ppnt++;
	}

	elf_ppnt = elf_phdata;
	for (i = 0; i < loc->elf_ex.e_phnum; i++, elf_ppnt++)
		switch (elf_ppnt->p_type) {
		case PT_GNU_STACK:
			if (elf_ppnt->p_flags & PF_X)
				executable_stack = EXSTACK_ENABLE_X;
			else
				executable_stack = EXSTACK_DISABLE_X;
			break;

		case PT_LOPROC ... PT_HIPROC:
			break;
		}

	/* Some simple consistency checks for the interpreter */
	if (elf_interpreter) {
		retval = -ENOEXEC;
		/* No support for dynamic linking */
		goto out_free_dentry;
	}

	/* Flush all traces of the currently running executable */
	retval = flush_old_exec(bprm);
	if (retval)
		goto out_free_dentry;

	/* Omitting process (task_struct) 'personality' related code */

	setup_new_exec(bprm);
	
	/* Omitting install_exec_creds(bprm) */

	/* Do this so that we can load the interpreter, if need be.  We will
	   change some of these later */
	retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP), executable_stack);
	if (retval < 0)
		goto out_free_dentry;
	
	bprm->proc->mm->start_stack = bprm->p;

	/* Now we do a little grungy work by mmapping the ELF image into
	   the correct location in memory. */
	for(i = 0, elf_ppnt = elf_phdata;
	    i < loc->elf_ex.e_phnum; i++, elf_ppnt++) {
		int elf_prot = 0, elf_flags;
		unsigned long k, vaddr;
		unsigned long total_size = 0;

		if (elf_ppnt->p_type != PT_LOAD)
			continue;

		if (unlikely (elf_brk > elf_bss)) {
			unsigned long nbyte;
	            
			/* There was a PT_LOAD segment with p_memsz > p_filesz
			   before this one. Map anonymous pages, if needed,
			   and clear the area.  */
			retval = set_brk(bprm->proc, elf_bss + load_bias,
					 elf_brk + load_bias);
			if (retval)
				goto out_free_dentry;
			nbyte = ELF_PAGEOFFSET(elf_bss);
			if (nbyte) {
				nbyte = ELF_MIN_ALIGN - nbyte;
				if (nbyte > elf_brk - elf_bss)
					nbyte = elf_brk - elf_bss;
				if (clear_user((void *)elf_bss +
							load_bias, nbyte)) {
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
		if (loc->elf_ex.e_type == ET_EXEC || load_addr_set) {
			elf_flags |= MAP_FIXED;
		} else if (loc->elf_ex.e_type == ET_DYN) {
			/* Shared object files not supported. 
			 * Should not come here as type is verified at the very beginning.
			 */
			retval = -ENOEXEC;
			goto out_free_dentry;
		}

		error = elf_map(bprm->proc, bprm->file, load_bias + vaddr, elf_ppnt,
				elf_prot, elf_flags, total_size);
		if (BAD_ADDR(error)) {
			retval = IS_ERR((void *)error) ?
				PTR_ERR((void*)error) : -EINVAL;
			goto out_free_dentry;
		}

		if (!load_addr_set) {
			load_addr_set = 1;
			load_addr = (elf_ppnt->p_vaddr - elf_ppnt->p_offset);
			if (loc->elf_ex.e_type == ET_DYN) {
				/* Shared object files not supported. 
				 * Should not come here as type is verified at the very beginning.
				 */
				retval = -ENOEXEC;
				goto out_free_dentry;
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
			goto out_free_dentry;
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

	/* Calling set_brk effectively mmaps the pages that we need
	 * for the bss and break sections.  We must do this before
	 * mapping in the interpreter, to make sure it doesn't wind
	 * up getting placed where the bss needs to go.
	 */
	retval = set_brk(bprm->proc, elf_bss, elf_brk);
	if (retval)
		goto out_free_dentry;
	if (likely(elf_bss != elf_brk) && unlikely(padzero(elf_bss))) {
		retval = -EFAULT; /* Nobody gets to see this, but.. */
		goto out_free_dentry;
	}

	if (elf_interpreter) {
		/* Dynamic linking not supported */
		retval = -ENOEXEC;
		goto out_free_dentry;
	} else {
		elf_entry = loc->elf_ex.e_entry;
		if (BAD_ADDR(elf_entry)) {
			retval = -EINVAL;
			goto out_free_dentry;
		}
	}

	kfree(elf_phdata);

#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
		goto out;
#endif

	retval = create_elf_tables(bprm, &loc->elf_ex,
			  load_addr, interp_load_addr);
	if (retval < 0)
		goto out;
	
	mm = bprm->proc->mm;

	mm->end_code = end_code;
	mm->start_code = start_code;
	mm->start_data = start_data;
	mm->end_data = end_data;
	mm->start_stack = bprm->p;
	
	/*
         * Randomization not included in the first parse.
         *
	 if ((bprm->proc->flags & PF_RANDOMIZE) && (randomize_va_space > 1)) {
		mm->start_brk = mm->brk;
	 } 
         */

#ifdef ELF_PLAT_INIT
	goto out_free_dentry;
#endif

	//start_thread(regs, elf_entry, bprm->p);
	/* Need to pack the response in the desc and send the data back to the processor */
	retval = 0;
	
out:
	kfree(loc);
out_ret:
	return retval;

	/* error cleanup */
out_free_dentry:
out_free_ph:
	kfree(elf_phdata);
	goto out;
}

struct lego_binfmt elf_format = {
	.load_binary	= load_elf_binary
};
