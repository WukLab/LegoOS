/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/errno.h>
#include <lego/linkage.h>
#include <asm/percpu.h>
#include <asm/asm.h>
#include <asm/extable.h>
#include <asm/thread_info.h>

#include <generated/asm-offsets.h>

/*
 * __put_user_X
 *
 * Inputs:	%eax[:%edx] contains the data
 *		%ecx contains the address
 *
 * Outputs:	%eax is error code (0 or -EFAULT)
 *
 * These functions should not modify any other registers,
 * as they get called from within inline assembly.
 */

#define ENTER	mov PER_CPU_VAR(current_task), %_ASM_BX
#define EXIT	ASM_CLAC ;	\
		ret

.text
ENTRY(__put_user_1)
	ENTER
	cmp TASK_addr_limit(%_ASM_BX),%_ASM_CX
	jae bad_put_user
	ASM_STAC
1:	movb %al,(%_ASM_CX)
	xor %eax,%eax
	EXIT
ENDPROC(__put_user_1)

ENTRY(__put_user_2)
	ENTER
	mov TASK_addr_limit(%_ASM_BX),%_ASM_BX
	sub $1,%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae bad_put_user
	ASM_STAC
2:	movw %ax,(%_ASM_CX)
	xor %eax,%eax
	EXIT
ENDPROC(__put_user_2)

ENTRY(__put_user_4)
	ENTER
	mov TASK_addr_limit(%_ASM_BX),%_ASM_BX
	sub $3,%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae bad_put_user
	ASM_STAC
3:	movl %eax,(%_ASM_CX)
	xor %eax,%eax
	EXIT
ENDPROC(__put_user_4)

ENTRY(__put_user_8)
	ENTER
	mov TASK_addr_limit(%_ASM_BX),%_ASM_BX
	sub $7,%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae bad_put_user
	ASM_STAC
4:	mov %_ASM_AX,(%_ASM_CX)
#ifdef CONFIG_X86_32
5:	movl %edx,4(%_ASM_CX)
#endif
	xor %eax,%eax
	EXIT
ENDPROC(__put_user_8)

bad_put_user:
	movl $-EFAULT,%eax
	EXIT
END(bad_put_user)

	_ASM_EXTABLE(1b,bad_put_user)
	_ASM_EXTABLE(2b,bad_put_user)
	_ASM_EXTABLE(3b,bad_put_user)
	_ASM_EXTABLE(4b,bad_put_user)
#ifdef CONFIG_X86_32
	_ASM_EXTABLE(5b,bad_put_user)
#endif
