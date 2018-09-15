/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Flags for vma and mmap related syscalls
 * Used by both processor and memory managers
 */

#ifndef _LEGO_MMAP_H_
#define _LEGO_MMAP_H_

#include <lego/types.h>

/* mremap() flags */
#define MREMAP_MAYMOVE	1
#define MREMAP_FIXED	2

/* mmap() flags */
#define PROT_READ	0x01		/* page can be read */
#define PROT_WRITE	0x02		/* page can be written */
#define PROT_EXEC	0x04		/* page can be executed */
#define PROT_SEM	0x08		/* page may be used for atomic ops */
#define PROT_NONE	0x00		/* page can not be accessed */
#define PROT_GROWSDOWN	0x01000000	/* mprotect flag: extend change to start of growsdown vma */
#define PROT_GROWSUP	0x02000000	/* mprotect flag: extend change to end of growsup vma */

/* mmap() flags */
#define MAP_SHARED	0x01		/* Share changes */
#define MAP_PRIVATE	0x02		/* Changes are private */
#define MAP_TYPE	0x0f		/* Mask for type of mapping */
#define MAP_FIXED	0x10		/* Interpret addr exactly */
#define MAP_ANONYMOUS	0x20		/* don't use a file */
#define MAP_GROWSDOWN	0x0100		/* stack-like segment */
#define MAP_DENYWRITE	0x0800		/* ETXTBSY */
#define MAP_EXECUTABLE	0x1000		/* mark it as an executable */
#define MAP_LOCKED	0x2000		/* pages are locked */

/*
 * vm_flags in vm_area_struct and p_vm_area_struct
 * Used by both processor and memory managers
 */
#define VM_NONE		0x00000000

#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

/* mprotect() hardcodes VM_MAYREAD >> 4 == VM_READ, and so for r/w/x bits. */
#define VM_MAYREAD	0x00000010	/* limits for mprotect() etc */
#define VM_MAYWRITE	0x00000020
#define VM_MAYEXEC	0x00000040
#define VM_MAYSHARE	0x00000080

#define VM_GROWSUP	VM_NONE
#define VM_GROWSDOWN	0x00000100	/* general info on the segment */
#define VM_UFFD_MISSING	0x00000200	/* missing pages tracking */
#define VM_PFNMAP	0x00000400	/* Page-ranges managed without "struct page", just pure PFN */
#define VM_DENYWRITE	0x00000800	/* ETXTBSY on write attempts.. */
#define VM_UFFD_WP	0x00001000	/* wrprotect pages tracking */

#define VM_LOCKED	0x00002000
#define VM_IO           0x00004000	/* Memory mapped I/O or similar */

#define VM_SEQ_READ	0x00008000	/* App will access data sequentially */
#define VM_RAND_READ	0x00010000	/* App will not benefit from clustered reads */

#define VM_DONTCOPY	0x00020000      /* Do not copy this vma on fork */
#define VM_DONTEXPAND	0x00040000	/* Cannot expand with mremap() */
#define VM_LOCKONFAULT	0x00080000	/* Lock the pages covered when they are faulted in */
#define VM_ACCOUNT	0x00100000	/* Is a VM accounted object */
#define VM_NORESERVE	0x00200000	/* should the VM suppress accounting */
#define VM_HUGETLB	0x00400000	/* Huge TLB Page VM */
#define VM_ARCH_1	0x01000000	/* Architecture-specific flag */
#define VM_ARCH_2	0x02000000
#define VM_DONTDUMP	0x04000000	/* Do not include in the core dump */

#ifdef CONFIG_MEM_SOFT_DIRTY
# define VM_SOFTDIRTY	0x08000000	/* Not soft dirty clean area */
#else
# define VM_SOFTDIRTY	0
#endif

#define VM_MIXEDMAP	0x10000000	/* Can contain "struct page" and pure PFN pages */
#define VM_HUGEPAGE	0x20000000	/* MADV_HUGEPAGE marked this vma */
#define VM_NOHUGEPAGE	0x40000000	/* MADV_NOHUGEPAGE marked this vma */
#define VM_MERGEABLE	0x80000000	/* KSM may merge identical pages */

/*
 * Special vmas that are non-mergable, non-mlock()able.
 */
#define VM_SPECIAL		(VM_IO | VM_PFNMAP)

#define VM_DATA_DEFAULT_FLAGS	(VM_READ | VM_WRITE) 

#define VM_STACK		VM_GROWSDOWN
#define VM_STACK_DEFAULT_FLAGS	VM_DATA_DEFAULT_FLAGS
#define VM_STACK_FLAGS		(VM_STACK | VM_STACK_DEFAULT_FLAGS)

/* Bits set in the VMA until the stack is in its final location */
#define VM_STACK_INCOMPLETE_SETUP	(VM_RAND_READ | VM_SEQ_READ)

static inline bool is_cow_mapping(vm_flags_t flags)
{
	return (flags & (VM_SHARED | VM_WRITE)) == VM_WRITE;
}

/*
 * On almost all architectures and configurations, 0 can be used as the
 * upper ceiling to free_pgtables(): on many architectures it has the same
 * effect as using TASK_SIZE.  However, there is one configuration which
 * must impose a more careful limit, to avoid freeing kernel pgtables.
 */
#define FIRST_USER_ADDRESS	0UL
#define USER_PGTABLES_CEILING	0UL

/*
 * Default maximum number of active map areas, this limits the number of vmas
 * per mm struct. Users can overwrite this number by sysctl but there is a
 * problem.
 *
 * When a program's coredump is generated as ELF format, a section is created
 * per a vma. In ELF, the number of sections is represented in unsigned short.
 * This means the number of sections should be smaller than 65535 at coredump.
 * Because the kernel adds some informative sections to a image of program at
 * generating coredump, we need some margin. The number of extra sections is
 * 1-3 now and depends on arch. We use "5" as safe margin, here.
 *
 * ELF extended numbering allows more than 65535 sections, so 16-bit bound is
 * not a hard limit any more. Although some userspace tools can be surprised by
 * that.
 */
#define MAPCOUNT_ELF_CORE_MARGIN	(5)
#define DEFAULT_MAX_MAP_COUNT	(USHRT_MAX - MAPCOUNT_ELF_CORE_MARGIN)

#endif /* _LEGO_MMAP_H_ */
