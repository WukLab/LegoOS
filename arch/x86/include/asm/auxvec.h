/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_AUXVEC_H_
#define _ASM_X86_AUXVEC_H_

/*
 * Architecture-neutral AT_ values in 0-17, leave some room
 * for more of them, start the x86-specific ones at 32.
 */
#ifdef __i386__
#define AT_SYSINFO		32
#endif
#define AT_SYSINFO_EHDR		33

/* entries in ARCH_DLINFO: */
#if defined(CONFIG_IA32_EMULATION) || !defined(CONFIG_X86_64)
# define AT_VECTOR_SIZE_ARCH 2
#else /* else it's non-compat x86-64 */
# define AT_VECTOR_SIZE_ARCH 1
#endif

/* TODO vdso */
#define vdso64_enabled 0

/* x86-64*/
#define ARCH_DLINFO							\
do {									\
	if (vdso64_enabled)						\
		NEW_AUX_ENT(AT_SYSINFO_EHDR, 0);			\
	else								\
		NEW_AUX_ENT(AT_SYSINFO_EHDR, 0);			\
} while (0)

/* As a historical oddity, the x32 and x86_64 vDSOs are controlled together. */
# define ARCH_DLINFO_X32						\
do {									\
	if (vdso64_enabled)						\
		NEW_AUX_ENT(AT_SYSINFO_EHDR, 0);			\
} while (0)

# define AT_SYSINFO		32

# define COMPAT_ARCH_DLINFO	ARCH_DLINFO_IA32
# define COMPAT_ELF_ET_DYN_BASE	(TASK_UNMAPPED_BASE + 0x1000000)

#endif /* _ASM_X86_AUXVEC_H_ */
