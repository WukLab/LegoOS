/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_SECTIONS_H_
#define _LEGO_SECTIONS_H_

/*
 * References to section boudaries defined in linker script.
 * Every architecture must contain sections listed below.
 * See arch/$(ARCH)/kernel/vmImage.ld.S for details.
 */

extern char __text[];	/* including head bootstrap code */
extern char __stext[], __etext[];
extern char __srodata[], __erodata[];
extern char __sdata[], __edata[];
extern char __sinittext[], __einittext[];
extern char __sinitdata[], __einitdata[];
extern char __bss_start[], __bss_end[];
extern char __end[];

#endif /* _LEGO_SECTIONS_H_ */
