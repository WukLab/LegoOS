/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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

	.text
ENTRY(__get_user_1)
	mov PER_CPU_VAR(current_task), %_ASM_DX
	cmp TASK_addr_limit(%_ASM_DX),%_ASM_AX
	jae bad_get_user
1:	movzbl (%_ASM_AX),%edx
	xor %eax,%eax
	ret
ENDPROC(__get_user_1)

ENTRY(__get_user_2)
	add $1,%_ASM_AX
	jc bad_get_user
	mov PER_CPU_VAR(current_task), %_ASM_DX
	cmp TASK_addr_limit(%_ASM_DX),%_ASM_AX
	jae bad_get_user
2:	movzwl -1(%_ASM_AX),%edx
	xor %eax,%eax
	ret
ENDPROC(__get_user_2)

ENTRY(__get_user_4)
	add $3,%_ASM_AX
	jc bad_get_user
	mov PER_CPU_VAR(current_task), %_ASM_DX
	cmp TASK_addr_limit(%_ASM_DX),%_ASM_AX
	jae bad_get_user
3:	movl -3(%_ASM_AX),%edx
	xor %eax,%eax
	ret
ENDPROC(__get_user_4)

ENTRY(__get_user_8)
#ifdef CONFIG_X86_64
	add $7,%_ASM_AX
	jc bad_get_user
	mov PER_CPU_VAR(current_task), %_ASM_DX
	cmp TASK_addr_limit(%_ASM_DX),%_ASM_AX
	jae bad_get_user
4:	movq -7(%_ASM_AX),%rdx
	xor %eax,%eax
	ret
#else
	add $7,%_ASM_AX
	jc bad_get_user_8
	mov PER_CPU_VAR(current_task), %_ASM_DX
	cmp TASK_addr_limit(%_ASM_DX),%_ASM_AX
	jae bad_get_user_8
4:	movl -7(%_ASM_AX),%edx
5:	movl -3(%_ASM_AX),%ecx
	xor %eax,%eax
	ret
#endif
ENDPROC(__get_user_8)

bad_get_user:
	xor %edx,%edx
	mov $(-EFAULT),%_ASM_AX
	ret
END(bad_get_user)

#ifdef CONFIG_X86_32
bad_get_user_8:
	xor %edx,%edx
	xor %ecx,%ecx
	mov $(-EFAULT),%_ASM_AX
	ret
END(bad_get_user_8)
#endif

	_ASM_EXTABLE(1b,bad_get_user)
	_ASM_EXTABLE(2b,bad_get_user)
	_ASM_EXTABLE(3b,bad_get_user)
#ifdef CONFIG_X86_64
	_ASM_EXTABLE(4b,bad_get_user)
#else
	_ASM_EXTABLE(4b,bad_get_user_8)
	_ASM_EXTABLE(5b,bad_get_user_8)
#endif
