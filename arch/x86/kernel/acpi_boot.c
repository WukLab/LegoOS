/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/asm.h>
#include <asm/apic.h>

#include <lego/acpi.h>
#include <lego/kernel.h>
#include <lego/early_ioremap.h>

int acpi_lapic;
int acpi_ioapic;
u64 acpi_lapic_addr = APIC_DEFAULT_PHYS_BASE;

void __init acpi_boot_table_init(void)
{

}
