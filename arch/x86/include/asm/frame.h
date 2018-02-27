/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_FRAME_H_
#define _ASM_X86_FRAME_H_

#include <asm/asm.h>

/*
 * These are stack frame creation macros.  They should be used by every
 * callable non-leaf asm function to make kernel stack traces more reliable.
 */

#ifdef CONFIG_FRAME_POINTER

#ifdef __ASSEMBLY__

.macro FRAME_BEGIN
	push %_ASM_BP
	_ASM_MOV %_ASM_SP, %_ASM_BP
.endm

.macro FRAME_END
	pop %_ASM_BP
.endm

#else /* !__ASSEMBLY__ */

#define FRAME_BEGIN				\
	"push %" _ASM_BP "\n"			\
	_ASM_MOV "%" _ASM_SP ", %" _ASM_BP "\n"

#define FRAME_END "pop %" _ASM_BP "\n"

#endif /* __ASSEMBLY__ */

#define FRAME_OFFSET __ASM_SEL(4, 8)

#else /* !CONFIG_FRAME_POINTER */

#define FRAME_BEGIN
#define FRAME_END
#define FRAME_OFFSET 0

#endif /* CONFIG_FRAME_POINTER */

#endif /* _ASM_X86_FRAME_H */
