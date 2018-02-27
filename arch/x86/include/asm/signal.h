/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_SIGNAL_H_
#define _ASM_X86_SIGNAL_H_

#define _NSIG		64
#define _NSIG_BPW	64
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

typedef struct {
	unsigned long sig[_NSIG_WORDS];
} sigset_t;

/* non-uapi in-kernel SA_FLAGS for those indicates ABI for a signal frame */
#define SA_IA32_ABI	0x02000000u
#define SA_X32_ABI	0x01000000u

#ifndef CONFIG_COMPAT
typedef sigset_t compat_sigset_t;
#endif

#define __ARCH_HAS_SA_RESTORER

extern void do_signal(struct pt_regs *regs);

#endif /* _ASM_X86_SIGNAL_H_ */
