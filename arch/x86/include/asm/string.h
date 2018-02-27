/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_STRING_H_
#define _ASM_X86_STRING_H_

#ifdef CONFIG_X86_32
# error "<asm/string_32.h> needed"
#else
# include <asm/string_64.h>
#endif

#endif /* _ASM_X86_STRING_H_ */
