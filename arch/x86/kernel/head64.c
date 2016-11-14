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
#include <asm/pgtable.h>

#include <lego/init.h>
#include <lego/string.h>
#include <lego/linkage.h>
#include <lego/sections.h>

extern pgd_t early_level4_pgt[PTRS_PER_PGD];
pmdval_t early_pmd_flags = __PAGE_KERNEL_LARGE & ~(_PAGE_GLOBAL | _PAGE_NX);

/* Wipe all early page tables except for the kernel symbol map */
static void __init reset_early_page_tables(void)
{
	memset(early_level4_pgt, 0, sizeof(pgd_t)*(PTRS_PER_PGD-1));
	write_cr3(__pa(early_level4_pgt));
}

static void __init clear_bss(void)
{
	memset(__bss_start, 0,
		(unsigned long)__bss_end - (unsigned long)__bss_start);
}

/*
 * Copy the real-mode data to a safe place
 * and also save the command line
 */
static void __init copy_bootdata(char *real_mode_data)
{
	char *command_line;
	unsigned long cmd_line_ptr;

	memcpy(&boot_params, real_mode_data, sizeof(boot_params));

	cmd_line_ptr = boot_params.hdr.cmd_line_ptr;
	if (cmd_line_ptr) {
		command_line = __va(cmd_line_ptr);
		memcpy(boot_command_line, command_line, COMMAND_LINE_SIZE);
	}
}

/*
 * This is called from the assembly head code
 * Do some architecture setup and then jump to generic start kernel
 */
asmlinkage __visible void __init x86_64_start_kernel(char *real_mode_data)
{
	reset_early_page_tables();

	clear_bss();
	copy_bootdata(__va(real_mode_data));

	/* Call into real start kernel... */
	start_kernel();
}
