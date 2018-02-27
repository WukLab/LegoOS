/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_KDEBUG_H_
#define _ASM_X86_KDEBUG_H_

extern void die(const char *, struct pt_regs *,long);
extern int __die(const char *, struct pt_regs *, long);

#endif /* _ASM_X86_KDEBUG_H_ */
