/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PTRACE_H_
#define _LEGO_PTRACE_H_

#include <asm/ptrace.h>

#ifndef current_pt_regs
#define current_pt_regs()	task_pt_regs(current)
#endif

#endif /* _LEGO_PTRACE_H_ */
