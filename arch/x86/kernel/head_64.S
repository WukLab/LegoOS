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
	movq	$1024, %rax
1:
	movq	$1b, %rbx
