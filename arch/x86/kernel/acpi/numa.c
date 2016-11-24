/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "SRAT ACPI: " fmt

#include <asm/asm.h>
#include <asm/apic.h>
#include <asm/processor.h>
#include <asm/irq_vectors.h>

#include <lego/acpi.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/early_ioremap.h>

void __init acpi_boot_numa_init(void)
{

}
