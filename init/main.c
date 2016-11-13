/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/tty.h>
#include <lego/panic.h>
#include <lego/kernel.h>
#include <lego/start_kernel.h>

static void hlt(void)
{
	asm (
		"1: hlt\n"
		"jmp 1b\n"
	);
}

asmlinkage void __init start_kernel(void)
{
	/* Prepare output first */
	tty_init();

	printk("Welcome to: %s",lego_banner);

	/* Architecture-Specific Initialization */
	setup_arch();

	hlt();
}
