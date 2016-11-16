/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/asm.h>
#include <asm/page.h>
#include <asm/setup.h>

#include <lego/bug.h>
#include <lego/tty.h>
#include <lego/irq.h>
#include <lego/init.h>
#include <lego/kernel.h>

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];

asmlinkage void __init start_kernel(void)
{
	local_irq_disable();

	/* Prepare output first */
	tty_init();

	pr_info("%s", lego_banner);
	pr_info("Command line: %s\n", boot_command_line);

	/* Architecture-Specific Initialization */
	setup_arch();

	BUG();
}
