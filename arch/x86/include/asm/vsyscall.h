/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_VSYSCALL_H_
#define _ASM_X86_VSYSCALL_H_

#include <lego/ptrace.h>

enum vsyscall_num {
	__NR_vgettimeofday,
	__NR_vtime,
	__NR_vgetcpu,
};

#define VSYSCALL_ADDR (-10UL << 20)

#ifdef CONFIG_X86_VSYSCALL_EMULATION
void map_vsyscall(void);

/*
 * Called on instruction fetch fault in vsyscall page.
 * Returns true if handled.
 */
bool emulate_vsyscall(struct pt_regs *regs, unsigned long address);
#else
static inline void map_vsyscall(void) {}
static inline bool emulate_vsyscall(struct pt_regs *regs, unsigned long address)
{
	return false;
}
#endif

#endif /* _ASM_X86_VSYSCALL_H_ */
