/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Parameters used by boot setup code
 */

#ifndef _ASM_X86_BOOT_H_
#define _ASM_X86_BOOT_H_

/* Internal svga startup constants */
#define NORMAL_VGA	0xffff		/* 80x25 mode */
#define EXTENDED_VGA	0xfffe		/* 80x50 mode */
#define ASK_VGA		0xfffd		/* ask for it at bootup */

/* Physical address where kernel should be loaded: */
#define LOAD_PHYSICAL_ADDR \
	(CONFIG_PHYSICAL_START + CONFIG_PHYSICAL_ALIGN - 1) \
	& ~(CONFIG_PHYSICAL_ALIGN - 1)

#endif /* _ASM_X86_BOOT_H_ */
