/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_SETUP_H_
#define _ASM_X86_SETUP_H_

/*
 * The setup.h is used by both 16-bit setup kernel image
 * and the setup.c in 64-bit kernel.
 */

#define COMMAND_LINE_SIZE	2048

#define OLD_CL_MAGIC		0xA33F
#define OLD_CL_ADDRESS		0x020	/* Relative to real mode data */
#define NEW_CL_POINTER		0x228	/* Relative to real mode data */

#ifndef __ASSEMBLY__

#include <asm/bootparam.h>
#include <lego/linkage.h>
#include <lego/compiler.h>

extern struct boot_params boot_params;

void __init setup_arch(void);
asmlinkage __visible void __init x86_64_start_kernel(char *real_mode_data);

#endif /* __ASSEMBLY */

#endif /* _ASM_X86_SETUP_H_ */
