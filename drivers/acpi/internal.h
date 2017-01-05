/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

void
acpi_tb_install_table_with_override(struct acpi_table_desc *new_table_desc,
				    u8 override, u32 *table_index);

void
acpi_tb_init_table_descriptor(struct acpi_table_desc *table_desc,
			      u64 address, struct acpi_table_header *table);

void
acpi_tb_print_table_header(unsigned long address, struct acpi_table_header *header);

int acpi_tb_validate_table(struct acpi_table_desc *table_desc);
void acpi_tb_invalidate_table(struct acpi_table_desc *table_desc);

void acpi_put_table(struct acpi_table_header *table);
int acpi_get_table(char *signature,
	       u32 instance, struct acpi_table_header ** out_table);

#define ACPI_MAX_TABLES 128
extern u32 nr_acpi_tables;
extern struct acpi_table_desc acpi_tables[ACPI_MAX_TABLES];
