/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/page.h>
#include <asm/pgtable.h>
#include <lego/linkage.h>

	.section ".init.data", "aw", @progbits
	.code16
GLOBAL(trampoline_start)
1:
	xor	%ax, %ax
	hlt
	jmp	1b

	.align PAGE_SIZE
GLOBAL(trampoline_end)
