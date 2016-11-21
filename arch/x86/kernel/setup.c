/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/apic.h>
#include <asm/e820.h>
#include <asm/desc.h>
#include <asm/page.h>
#include <asm/traps.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include <asm/segment.h>
#include <asm/processor.h>
#include <asm/bootparam.h>
#include <asm/trampoline.h>

#include <lego/kernel.h>
#include <lego/early_ioremap.h>

/* Data that was collected by real-mode kernel */
struct boot_params boot_params;

struct gdt_page gdt_page = { .gdt = {
	/*
	 * We need valid kernel segments for data and code in long mode too
	 * IRET will check the segment types  kkeil 2000/10/28
	 * Also sysret mandates a special GDT layout
	 *
	 * TLS descriptors are currently at a different place compared to i386.
	 * Hopefully nobody expects them at a fixed place (Wine?)
	 */
	[GDT_ENTRY_KERNEL32_CS]		= GDT_ENTRY_INIT(0xc09b, 0, 0xfffff),
	[GDT_ENTRY_KERNEL_CS]		= GDT_ENTRY_INIT(0xa09b, 0, 0xfffff),
	[GDT_ENTRY_KERNEL_DS]		= GDT_ENTRY_INIT(0xc093, 0, 0xfffff),
	[GDT_ENTRY_DEFAULT_USER32_CS]	= GDT_ENTRY_INIT(0xc0fb, 0, 0xfffff),
	[GDT_ENTRY_DEFAULT_USER_DS]	= GDT_ENTRY_INIT(0xc0f3, 0, 0xfffff),
	[GDT_ENTRY_DEFAULT_USER_CS]	= GDT_ENTRY_INIT(0xa0fb, 0, 0xfffff),
} };

/*
 * setup_arch
 * x86-64 specific initiliazation
 */
void __init setup_arch(void)
{
	early_cpu_init();
	early_ioremap_init();

	/* Parse e820 table */
	setup_physical_memory();

	/*
	 * Load interrupt handlers
	 * and init everthing about BSP
	 */
	trap_init();
	cpu_init();

	check_x2apic();
	setup_apic_driver();
	init_apic_mappings();

	copy_trampoline();
}
