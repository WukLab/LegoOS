/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/pci.h>
#include <lego/kernel.h>
#include <asm/pci.h>

/*
 * mmconfig-shared.c - Low-level direct PCI config space access via
 *                     MMCONFIG - common code between i386 and x86-64.
 *
 * This code does:
 * - known chipset handling
 * - ACPI decoding and validation
 *
 * Per-architecture code takes care of the mappings and accesses
 * themselves.
 */

#define PREFIX "PCI: "

void __init pci_mmcfg_early_init(void)
{
}
