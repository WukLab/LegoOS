/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/mm.h>
#include <lego/kernel.h>
#include <lego/tracepoint.h>
#include <lego/distvm.h>
#include <memory/vm.h>
#include <memory/file_types.h>

#define __def_vmaflag_names						\
	{VM_READ,			"read"		},		\
	{VM_WRITE,			"write"		},		\
	{VM_EXEC,			"exec"		},		\
	{VM_SHARED,			"shared"	},		\
	{VM_MAYREAD,			"mayread"	},		\
	{VM_MAYWRITE,			"maywrite"	},		\
	{VM_MAYEXEC,			"mayexec"	},		\
	{VM_MAYSHARE,			"mayshare"	},		\
	{VM_GROWSDOWN,			"growsdown"	},		\
	{VM_UFFD_MISSING,		"uffd_missing"	},		\
	{VM_PFNMAP,			"pfnmap"	},		\
	{VM_DENYWRITE,			"denywrite"	},		\
	{VM_UFFD_WP,			"uffd_wp"	},		\
	{VM_LOCKED,			"locked"	},		\
	{VM_IO,				"io"		},		\
	{VM_SEQ_READ,			"seqread"	},		\
	{VM_RAND_READ,			"randread"	},		\
	{VM_DONTCOPY,			"dontcopy"	},		\
	{VM_DONTEXPAND,			"dontexpand"	},		\
	{VM_LOCKONFAULT,		"lockonfault"	},		\
	{VM_ACCOUNT,			"account"	},		\
	{VM_NORESERVE,			"noreserve"	},		\
	{VM_HUGETLB,			"hugetlb"	},		\
	{VM_ARCH_1,			"arch_1"	},		\
	{VM_ARCH_2,			"arch_2"	},		\
	{VM_DONTDUMP,			"dontdump"	},		\
	{VM_SOFTDIRTY,			"softdirty"	},		\
	{VM_MIXEDMAP,			"mixedmap"	},		\
	{VM_HUGEPAGE,			"hugepage"	},		\
	{VM_NOHUGEPAGE,			"nohugepage"	},		\
	{VM_MERGEABLE,			"mergeable"	}		\

const struct trace_print_flags vmaflag_names[] = {
	__def_vmaflag_names,
	{0, NULL}
};

void dump_vma_simple(const struct vm_area_struct *vma)
{
	struct lego_file *file = vma->vm_file;
	struct lego_mm_struct *mm = vma->vm_mm;
	unsigned long start = vma->vm_start;
	unsigned long end = vma->vm_end;
	vm_flags_t flags = vma->vm_flags;
	unsigned long long pgoff = 0;

	if (file)
		pgoff = vma->vm_pgoff << PAGE_SHIFT;

	pr_emerg("  %08lx-%08lx %c%c%c%c %08llx ",
		  start, end,
		  flags & VM_READ ? 'r' : '-',
		  flags & VM_WRITE ? 'w' : '-',
		  flags & VM_EXEC ? 'x' : '-',
		  flags & VM_MAYSHARE ? 's' : 'p',
		  pgoff);

	if (file)
		pr_cont("%s\n", file->filename);
	else {
		const char *name = NULL;

		if (!mm)
			name = "[vdso]";
		else if (vma->vm_start <= mm->brk &&
			 vma->vm_end >= mm->start_brk)
			name = "[heap]";
		else if (vma->vm_start <= mm->start_stack &&
			 vma->vm_end >= mm->start_stack)
			name = "[stack]";
		if (name)
			pr_cont("%s\n", name);
		else
			pr_cont("\n");
	}
}

void dump_vma(const struct vm_area_struct *vma)
{
	pr_emerg("\n"
		"vma %p start %p end %p\n"
		"next %p prev %p mm %p\n"
		"prot %lx vm_ops %pS\n"
		"pgoff %lx file %p f_op %pS\n"
		"flags: %#lx(%pGv)\n",
		vma, (void *)vma->vm_start, (void *)vma->vm_end, vma->vm_next,
		vma->vm_prev, vma->vm_mm,
		(unsigned long)pgprot_val(vma->vm_page_prot),
		vma->vm_ops,
		vma->vm_pgoff, vma->vm_file, vma->vm_file ? vma->vm_file->f_op : NULL,
		vma->vm_flags, &vma->vm_flags);
}

void dump_all_vmas_simple(struct lego_mm_struct *mm)
{
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	struct vma_tree **map = mm->vmrange_map;
	int idx = 0;
	for (idx = 0; idx < VMR_COUNT; idx++) {
		struct vma_tree *root = map[idx];
		struct vm_area_struct *vma;
		if (!root)
			continue;
		
		vma = root->mmap;
		while (vma) {
			dump_vma_simple(vma);
			vma = vma->vm_next;
		}

		idx = vmr_idx(VMR_ALIGN(root->end)) - 1;
	}
#else
	struct vm_area_struct *vma;

	vma = mm->mmap;

	while (vma) {
		dump_vma_simple(vma);
		vma = vma->vm_next;
	}
#endif
}

void dump_all_vmas(struct lego_mm_struct *mm)
{
#ifdef CONFIG_DISTRIBUTED_VMA_MEMORY
	struct vma_tree **map = mm->vmrange_map;
	int idx = 0;
	for (idx = 0; idx < VMR_COUNT; idx++) {
		struct vma_tree *root = map[idx];
		struct vm_area_struct *vma;
		if (!root)
			continue;
		
		vma = root->mmap;
		while (vma) {
			dump_vma(vma);
			vma = vma->vm_next;
		}

		idx = vmr_idx(VMR_ALIGN(root->end)) - 1;
	}
#else
	struct vm_area_struct *vma;

	vma = mm->mmap;

	while (vma) {
		dump_vma(vma);
		vma = vma->vm_next;
	}
#endif
}

void dump_lego_mm(const struct lego_mm_struct *mm)
{
	pr_emerg("\n"
		"mm %p mmap %p task_size %#lx\n"
		"get_unmapped_area %p\n"
		"mmap_base %#lx mmap_legacy_base %#lx highest_vm_end %#lx\n"
		"pgd %p mm_users %d mm_count %d nr_ptes %lu map_count %d\n"
		"total_vm %#lx\n"
		"data_vm %#lx exec_vm %#lx stack_vm %#lx\n"
		"start_code %#lx end_code %#lx start_data %#lx end_data %#lx\n"
		"start_bss %#lx\n"
		"start_brk %#lx brk %#lx start_stack %#lx\n"
		"arg_start %#lx arg_end %#lx env_start %#lx env_end %#lx\n"
		"def_flags: %#lx(%pGv)\n",

		mm, mm->mmap, mm->task_size,
		mm->get_unmapped_area,
		mm->mmap_base, mm->mmap_legacy_base, mm->highest_vm_end,
		mm->pgd, atomic_read(&mm->mm_users), atomic_read(&mm->mm_count),
		atomic_long_read((atomic_long_t *)&mm->nr_ptes), mm->map_count,
		mm->total_vm,
		mm->data_vm, mm->exec_vm, mm->stack_vm,
		mm->start_code, mm->end_code, mm->start_data, mm->end_data,
		mm->start_bss,
		mm->start_brk, mm->brk, mm->start_stack,
		mm->arg_start, mm->arg_end, mm->env_start, mm->env_end,
		mm->def_flags, &mm->def_flags
	);
}
