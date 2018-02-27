/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * RMWcc: Read-Modify-Write-Conditional-Code
 * Used to generate atomic operations and have an extra conditional test
 */

#ifndef _ASM_X86_RMWcc_
#define _ASM_X86_RMWcc_

#include <asm/asm.h>

#if !defined(__GCC_ASM_FLAG_OUTPUTS__) && defined(CC_HAVE_ASM_GOTO)

/* Use asm goto */

#define __GEN_RMWcc(fullop, var, cc, ...)				\
do {									\
	asm_volatile_goto (fullop "; j" #cc " %l[cc_label]"		\
			: : "m" (var), ## __VA_ARGS__ 			\
			: "memory" : cc_label);				\
	return 0;							\
cc_label:								\
	return 1;							\
} while (0)

#define GEN_UNARY_RMWcc(op, var, arg0, cc) 				\
	__GEN_RMWcc(op " " arg0, var, cc)

#define GEN_BINARY_RMWcc(op, var, vcon, val, arg0, cc)			\
	__GEN_RMWcc(op " %1, " arg0, var, cc, vcon (val))

#else /* defined(__GCC_ASM_FLAG_OUTPUTS__) || !defined(CC_HAVE_ASM_GOTO) */

/* Use flags output or a set instruction */

#define __GEN_RMWcc(fullop, var, cc, ...)				\
do {									\
	bool c;								\
	asm volatile (fullop ";" CC_SET(cc)				\
			: "+m" (var), CC_OUT(cc) (c)			\
			: __VA_ARGS__ : "memory");			\
	return c;							\
} while (0)

#define GEN_UNARY_RMWcc(op, var, arg0, cc)				\
	__GEN_RMWcc(op " " arg0, var, cc)

#define GEN_BINARY_RMWcc(op, var, vcon, val, arg0, cc)			\
	__GEN_RMWcc(op " %2, " arg0, var, cc, vcon (val))

#endif /* defined(__GCC_ASM_FLAG_OUTPUTS__) || !defined(CC_HAVE_ASM_GOTO) */

#endif /* _ASM_X86_RMWcc_ */
