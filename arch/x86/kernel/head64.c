/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/init.h>
#include <lego/string.h>
#include <lego/linkage.h>
#include <lego/sections.h>
#include <lego/screen_info.h>

#include <asm/asm.h>
#include <asm/desc.h>
#include <asm/page.h>
#include <asm/setup.h>
#include <asm/pgtable.h>
#include <asm/segment.h>
#include <asm/tlbflush.h>
#include <asm/fixmap.h>

extern pgd_t early_level4_pgt[PTRS_PER_PGD];
extern pmd_t early_dynamic_pgts[EARLY_DYNAMIC_PAGE_TABLES][PTRS_PER_PMD];
static unsigned int __initdata next_early_pgt = 2;
pmdval_t early_pmd_flags = __PAGE_KERNEL_LARGE & ~(_PAGE_GLOBAL | _PAGE_NX);

/* Wipe all early page tables except for the kernel symbol map */
static void __init reset_early_page_tables(void)
{
	memset(early_level4_pgt, 0, sizeof(pgd_t)*(PTRS_PER_PGD-1));
	next_early_pgt = 0;
	write_cr3(__pa(early_level4_pgt));
}

/* Create a new PMD entry */
int __init early_make_pgtable(unsigned long address)
{
	unsigned long physaddr = address - __PAGE_OFFSET;
	pgdval_t pgd, *pgd_p;
	pudval_t pud, *pud_p;
	pmdval_t pmd, *pmd_p;

	/* Invalid address or early pgt is done ?  */
	if (physaddr >= MAXMEM || read_cr3() != __pa(early_level4_pgt))
		return -1;

again:
	pgd_p = &early_level4_pgt[pgd_index(address)].pgd;
	pgd = *pgd_p;

	/*
	 * The use of __START_KERNEL_map rather than __PAGE_OFFSET here is
	 * critical --- early_dynamic_pgts[]'s virtual address base is
	 * __START_KERNEL_map.
	 */

	if (pgd)
		pud_p = (pudval_t *)((pgd & PTE_PFN_MASK) + __START_KERNEL_map - phys_base);
	else {
		if (next_early_pgt >= EARLY_DYNAMIC_PAGE_TABLES) {
			reset_early_page_tables();
			goto again;
		}

		pud_p = (pudval_t *)early_dynamic_pgts[next_early_pgt++];
		memset(pud_p, 0, sizeof(*pud_p) * PTRS_PER_PUD);
		*pgd_p = (pgdval_t)pud_p - __START_KERNEL_map + phys_base + _KERNPG_TABLE;
	}
	pud_p += pud_index(address);
	pud = *pud_p;

	if (pud)
		pmd_p = (pmdval_t *)((pud & PTE_PFN_MASK) + __START_KERNEL_map - phys_base);
	else {
		if (next_early_pgt >= EARLY_DYNAMIC_PAGE_TABLES) {
			reset_early_page_tables();
			goto again;
		}

		pmd_p = (pmdval_t *)early_dynamic_pgts[next_early_pgt++];
		memset(pmd_p, 0, sizeof(*pmd_p) * PTRS_PER_PMD);
		*pud_p = (pudval_t)pmd_p - __START_KERNEL_map + phys_base + _KERNPG_TABLE;
	}
	pmd = (physaddr & PMD_MASK) + early_pmd_flags;
	pmd_p[pmd_index(address)] = pmd;

	return 0;
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

/* Save screen info to another place */
static void __init copy_screen_info(void)
{
	screen_info = boot_params.screen_info;
}

/*
 * The early fault handlers, solely used to handle page fault
 * All other faults should NOT happen before the final initialization
 * of idt, which is the trap_init().
 */
extern const char
early_idt_handler_array[NUM_EXCEPTION_VECTORS][EARLY_IDT_HANDLER_SIZE];

static void __init load_early_idt_handlers(void)
{
	int i;

	for (i = 0; i < NUM_EXCEPTION_VECTORS; i++)
		set_intr_gate(i, (void *)early_idt_handler_array[i]);
	load_idt((const struct desc_ptr *)&idt_desc);
}

/*
 * This is called from the assembly head code
 * Do some architecture setup and then jump to generic start kernel
 */
asmlinkage __visible void __init x86_64_start_kernel(char *real_mode_data)
{
	BUILD_BUG_ON((__START_KERNEL_map & ~PMD_MASK) != 0);
	BUILD_BUG_ON((__START_KERNEL_map & ~PMD_MASK) != 0);
	BUILD_BUG_ON(__fix_to_virt(__end_of_fixed_addresses) <= MODULES_END);

	cr4_init_shadow();

	/* Clear its low-address identity-mapping */
	reset_early_page_tables();

	clear_bss();

	/*
	 * Clear the low-address identity-mapping,
	 * which is staticlly assigned in head_64.S for the [0-4G).
	 * Then, set the init_level4_pgt's kernel high mapping.
	 */
	clear_page(init_level4_pgt);
	init_level4_pgt[511] = early_level4_pgt[511];

	load_early_idt_handlers();

	copy_bootdata(__va(real_mode_data));
	copy_screen_info();

	start_kernel();
}
