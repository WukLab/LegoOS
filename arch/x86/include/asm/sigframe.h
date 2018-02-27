/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_SIGFRAME_H_
#define _ASM_X86_SIGFRAME_H_

#include <asm/ucontext.h>
#include <lego/compiler.h>

struct siginfo;

struct rt_sigframe {
	char __user *pretcode;
	struct ucontext uc;
	struct siginfo info;
	/* fp state follows here */
};

#endif /* _ASM_X86_SIGFRAME_H_ */
