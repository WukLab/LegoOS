/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/numa.h>
#include <asm/apic.h>
#include <asm/e820.h>
#include <asm/desc.h>
#include <asm/page.h>
#include <asm/traps.h>
#include <asm/setup.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include <asm/segment.h>
#include <asm/processor.h>
#include <asm/bootparam.h>
#include <asm/trampoline.h>

#include <lego/mm.h>
#include <lego/smp.h>
#include <lego/acpi.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/nodemask.h>
#include <lego/memblock.h>
#include <lego/early_ioremap.h>

/*
 * max_pfn_mapped:     highest direct mapped pfn over 4GB
 * The direct mapping only covers E820_RAM regions,
 * so the ranges and gaps are represented by pfn_mapped
 */
unsigned long max_pfn_mapped;

/*
 * max_pfn:	highest pfn of this machine
 * The largest physical page frame number reported by E820_RAM
 */
unsigned long max_pfn;

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

static unsigned long _brk_start = (unsigned long)__brk_start;
unsigned long _brk_end = (unsigned long)__brk_start;

void * __init extend_brk(size_t size, size_t align)
{
	size_t mask = align - 1;
	void *ret;

	/* brk is closed */
	BUG_ON(_brk_start == 0);
	BUG_ON(align & mask);

	_brk_end = (_brk_end + mask) & ~mask;
	BUG_ON((char *)(_brk_end + size) > __brk_limit);

	ret = (void *)_brk_end;
	_brk_end += size;

	memset(ret, 0, size);

	return ret;
}

static void __init reserve_brk(void)
{
	if (_brk_end > _brk_start)
		memblock_reserve(__pa(_brk_start),
				 _brk_end - _brk_start);

	/*
	 * Mark brk area as locked down
	 * and no longer taking any new allocations
	 */
	_brk_start = 0;
}

/*
 * setup_arch
 * x86-64 specific initiliazation
 */
void __init setup_arch(void)
{
	early_cpu_init();
	early_ioremap_init();

	/*
	 * Parse e820 table
	 */
	setup_physical_memory();
	max_pfn = e820_end_of_ram_pfn();

	/*
	 * Allocate early pgtable buffers
	 * and them fill brk into memblock
	 */
	early_alloc_pgt_buf();
	reserve_brk();

	/*
	 * Pass all RAM info into memblock
	 * Now memblock is fully functional:
	 */
	e820_fill_memblock();

	/* Setup identity mapping */
	init_mem_mapping();

	/*
	 * Load interrupt handlers after init_mem_mapping()
	 * Because we want the early page fault handlers to
	 * handle the __va() page fault before trap_init().
	 */
	trap_init();
	cpu_init();

	/*
	 * Before parsing ACPI tables,
	 * set default APIC driver first
	 */
	check_x2apic();
	setup_apic_driver();

	/*
	 * Map all ACPI tables
	 * and find possible SMP settings
	 */
	acpi_table_init();
	acpi_boot_parse_tables();

	/*
	 * Find and init NUMA from ACPI
	 * All NUMA related initilization can proceed
	 * after this call:
	 */
	acpi_boot_numa_init();

	/* APIC's final init */
	init_apic_mappings();

	/*
	 * Gosh, say goodbye to ACPI and APIC table parsing
	 * Welcome to the world of Operating System. Init the
	 * CPU id and Node id mapping:
	 */
	init_cpu_to_node();

	/*
	 * Prepare trampoline for APs
	 * and then boot them up
	 */
	copy_trampoline_code();

	native_cpu_up(1);
}
