/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "ACPI: " fmt

#include <lego/acpi.h>
#include <lego/kernel.h>

#include <asm/io.h>

#include "internal.h"

/*
 * Note:
 * This is a internal array for ACPI tables.
 * This array only store the physical and length of each ACPI table.
 * Nothing is mapped at normal. Tables will be mapped only after you
 * call acpi_get_and_map_table() and unmapped by calling acpi_unmap_table()
 *
 * We do this because early_ioremap slots are limited.
 */
u32 nr_acpi_tables = 0;
struct acpi_table_desc acpi_tables[ACPI_MAX_TABLES] __initdata;

static __init int
acpi_tb_get_next_table_descriptor(u32 *table_index,
				  struct acpi_table_desc **table_desc)
{
	u32 i;

	/* Ensure that there is room for the table in the Root Table List */
	if (nr_acpi_tables >= ACPI_MAX_TABLES) {
		pr_err("No room in acpi_tables[] for new table\n");
		return -ENOMEM;
	}

	i = nr_acpi_tables;
	nr_acpi_tables++;

	if (table_index)
		*table_index = i;
	if (table_desc)
		*table_desc = &acpi_tables[i];

	return 0;
}

void acpi_tb_install_table_with_override(struct acpi_table_desc *new_table_desc,
				         u8 override, u32 *table_index)
{
	u32 i;
	int ret;

	ret = acpi_tb_get_next_table_descriptor(&i, NULL);
	if (ret)
		return;

	acpi_tb_init_table_descriptor(&acpi_tables[i],
				      new_table_desc->address,
				      new_table_desc->pointer);

	acpi_tb_print_table_header(new_table_desc->address,
				   new_table_desc->pointer);

	*table_index = i;
}
