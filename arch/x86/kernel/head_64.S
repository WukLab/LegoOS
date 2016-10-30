/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 */

#include <asm/segment.h>
#include <disos/linkage.h>
#include <disos/compiler.h>

	.text
	.section ".head.text","ax"
	.code64
ENTRY(startup_64)
	/*
	 * At this point the CPU runs in 64-bit mode CS.L = 1 CS.D = 0,
	 * and an identity mapped page table is loaded. These identity
	 * mapped page tables map [0, 4GB).
	 *
	 * %rsi holds a physical pointer to bootparam structure
	 */


1:
	hlt
	jmp	1b
