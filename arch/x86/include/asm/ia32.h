/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_IA32_H_
#define _ASM_X86_IA32_H_

#ifdef CONFIG_IA32_EMULATION

#include <lego/compat.h>

/*
 * 32 bit structures for IA32 support.
 */
#include <asm/sigcontext.h>

/* signal.h */

struct ucontext_ia32 {
	unsigned int	  uc_flags;
	unsigned int 	  uc_link;
	compat_stack_t	  uc_stack;
	struct sigcontext_32 uc_mcontext;
	compat_sigset_t	  uc_sigmask;	/* mask last for extensibility */
};

/* This matches struct stat64 in glibc2.2, hence the absolutely
 * insane amounts of padding around dev_t's.
 */
struct stat64 {
	unsigned long long	st_dev;
	unsigned char		__pad0[4];

#define STAT64_HAS_BROKEN_ST_INO	1
	unsigned int		__st_ino;

	unsigned int		st_mode;
	unsigned int		st_nlink;

	unsigned int		st_uid;
	unsigned int		st_gid;

	unsigned long long	st_rdev;
	unsigned char		__pad3[4];

	long long		st_size;
	unsigned int		st_blksize;

	long long		st_blocks;/* Number 512-byte blocks allocated */

	unsigned 		st_atime;
	unsigned 		st_atime_nsec;
	unsigned 		st_mtime;
	unsigned 		st_mtime_nsec;
	unsigned 		st_ctime;
	unsigned 		st_ctime_nsec;

	unsigned long long	st_ino;
} __attribute__((packed));

#define IA32_STACK_TOP IA32_PAGE_OFFSET

#endif

#endif /* _ASM_X86_IA32_H_ */
