/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "ACPI: " fmt

#include <asm/asm.h>
#include <asm/apic.h>
#include <asm/processor.h>

#include <lego/acpi.h>
#include <lego/kernel.h>
#include <lego/early_ioremap.h>

int acpi_lapic;
int acpi_ioapic;
u64 acpi_lapic_addr = APIC_DEFAULT_PHYS_BASE;

static int __init acpi_parse_madt(struct acpi_table_header *table)
{
	struct acpi_table_madt *madt;

	if (!cpu_has(X86_FEATURE_APIC))
		return -EINVAL;

	madt = (struct acpi_table_madt *)table;
	if (WARN_ON(!madt))
		return -ENODEV;

	if (madt->address) {
		acpi_lapic_addr = (u64) madt->address;
		pr_info("Local APIC address %#x\n",
			madt->address);
	}

	return 0;
}

/**
 * acpi_boot_parse_madt
 * Process the Multiple APIC Description Table,
 * find all possible APIC and IO-APIC settings.
 */
static void acpi_boot_parse_madt(void)
{
	int ret;

	ret = acpi_parse_table(ACPI_SIG_MADT, acpi_parse_madt);
	if (ret)
		return;

}

/*
 * Parse ACPI tables one-by-one
 * - MADT: Multiple APIC Description Table
 */
void __init acpi_boot_parse_tables(void)
{
	acpi_boot_parse_madt();
}
