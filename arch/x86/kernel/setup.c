/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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
#include <asm/nops.h>
#include <asm/traps.h>
#include <asm/setup.h>
#include <asm/timex.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include <asm/segment.h>
#include <asm/vsyscall.h>
#include <asm/tlbflush.h>
#include <asm/processor.h>
#include <asm/bootparam.h>
#include <asm/trampoline.h>

#include <lego/mm.h>
#include <lego/smp.h>
#include <lego/acpi.h>
#include <lego/sched.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/jiffies.h>
#include <lego/nodemask.h>
#include <lego/memblock.h>
#include <lego/resource.h>
#include <lego/early_ioremap.h>

#if !defined(CONFIG_X86_PAE) || defined(CONFIG_X86_64)
__visible unsigned long mmu_cr4_features;
#else
__visible unsigned long mmu_cr4_features = X86_CR4_PAE;
#endif

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

/*
 * GDT table has to be per-cpu because the TSS segment has to be per-cpu
 */
DEFINE_PER_CPU_PAGE_ALIGNED(struct gdt_page, cpu_gdt_page) = { .gdt = {
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

static struct resource data_resource = {
	.name	= "Kernel data",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM
};

static struct resource code_resource = {
	.name	= "Kernel code",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM
};

static struct resource bss_resource = {
	.name	= "Kernel bss",
	.start	= 0,
	.end	= 0,
	.flags	= IORESOURCE_BUSY | IORESOURCE_SYSTEM_RAM
};

static struct resource standard_io_resources[] = {
	{ .name = "dma1", .start = 0x00, .end = 0x1f,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "pic1", .start = 0x20, .end = 0x21,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "timer0", .start = 0x40, .end = 0x43,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "timer1", .start = 0x50, .end = 0x53,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "keyboard", .start = 0x60, .end = 0x60,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "keyboard", .start = 0x64, .end = 0x64,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "dma page reg", .start = 0x80, .end = 0x8f,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "pic2", .start = 0xa0, .end = 0xa1,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "dma2", .start = 0xc0, .end = 0xdf,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO },
	{ .name = "fpu", .start = 0xf0, .end = 0xff,
		.flags = IORESOURCE_BUSY | IORESOURCE_IO }
};

static void __init reserve_standard_io_resources(void)
{
	int i;

	/* request I/O space for devices used on all i[345]86 PCs */
	for (i = 0; i < ARRAY_SIZE(standard_io_resources); i++)
		request_resource(&ioport_resource, &standard_io_resources[i]);

}

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

void __init early_setup_arch(void)
{
	/*
	 * Parse e820 table
	 */
	setup_physical_memory();
}

/*
 * setup_arch
 * x86-64 specific initiliazation
 * fixmaps are ready for use even before this is called.
 */
void __init setup_arch(void)
{
	memblock_reserve(__pa_symbol(__text),
		(unsigned long)__end - (unsigned long)__text);

	init_mm.start_code = (unsigned long)__text;
	init_mm.end_code = (unsigned long)__etext;
	init_mm.end_data = (unsigned long)__edata;
	init_mm.brk = _brk_end;

	early_cpu_init();
	iomem_resource.end = (1ULL << default_cpu_info.x86_phys_bits) - 1;

	code_resource.start = __pa_symbol(__text);
	code_resource.end = __pa_symbol(__etext)-1;
	data_resource.start = __pa_symbol(__etext);
	data_resource.end = __pa_symbol(__edata)-1;
	bss_resource.start = __pa_symbol(__bss_start);
	bss_resource.end = __pa_symbol(__bss_end)-1;

	BUG_ON(insert_resource(&iomem_resource, &code_resource));
	BUG_ON(insert_resource(&iomem_resource, &data_resource));
	BUG_ON(insert_resource(&iomem_resource, &bss_resource));

	reserve_standard_io_resources();

	early_ioremap_init();

	map_vsyscall();

	finish_e820_parsing();
	max_pfn = e820_end_of_ram_pfn();

	/*
	 * Offload user-defined e820 table to memblock.
	 * Note that e820 table does not say anything about node-memory
	 * affinity, hence memblock does not hold any node info at this point.
	 * The node info is set below either by x86_numa_init() or flat 0.
	 */
	e820_fill_memblock();

	/*
	 * Allocate early pgtable buffers
	 * and them fill brk into memblock
	 */
	early_alloc_pgt_buf();
	reserve_brk();

	/* Setup identity mapping */
	init_mem_mapping();

	/*
	 * Update mmu_cr4_features with the current CR4 value.
	 * This may not be necessary, but auditing all the early-boot
	 * CR4 manipulation would be needed to rule it out.
	 */
	mmu_cr4_features = read_cr4();

	/*
	 * Before parsing ACPI tables,
	 * set default APIC driver first
	 */
	check_x2apic();

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
	 * At this point, node-affinity is known, which we fetched from ACPI
	 * tables. So, the last step is let memblock know:
	 */
#ifdef CONFIG_NUMA
	x86_numa_init();
#else
	memblock_set_node(0, (phys_addr_t)ULLONG_MAX, &memblock.memory, 0);
#endif

	/*
	 * Load interrupt handlers after init_mem_mapping()
	 * Because we want the early page fault handlers to handle the __va()
	 * page fault before trap_init().
	 */
	trap_init();

	copy_trampoline_code();

	arch_init_ideal_nops();

	identify_cpu(&default_cpu_info);
	print_cpu_info(&default_cpu_info);

	alternative_instructions();
	pt_dump_init();

	pr_info("x86: setup_arch done\n");
}
