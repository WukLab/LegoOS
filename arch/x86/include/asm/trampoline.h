/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_TRAMPOLINE_H_
#define _ASM_X86_TRAMPOLINE_H_

void __init copy_trampoline_code(void);

extern unsigned int trampoline_start;
extern unsigned int trampoline_end;

#endif /* _ASM_X86_TRAMPOLINE_H_ */
