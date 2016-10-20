/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * Parameters used by boot setup code
 */

/* Internal svga startup constants */
#define NORMAL_VGA	0xffff		/* 80x25 mode */
#define EXTENDED_VGA	0xfffe		/* 80x50 mode */
#define ASK_VGA		0xfffd		/* ask for it at bootup */

/* Physical address where kernel should be loaded: */
#define LOAD_PHYSICAL_ADDR \
	(CONFIG_PHYSICAL_START + CONFIG_PHYSICAL_ALIGN - 1) \
	& ~(CONFIG_PHYSICAL_ALIGN - 1)
