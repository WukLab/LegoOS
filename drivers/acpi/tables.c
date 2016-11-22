/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "ACPI: " fmt

#include <lego/mm.h>
#include <lego/bug.h>
#include <lego/acpi.h>
#include <lego/ctype.h>
#include <lego/string.h>
#include <lego/kernel.h>
#include <lego/early_ioremap.h>

#include "acpi.h"

#define ACPI_MAX_TABLES 128
static struct acpi_table_desc initial_tables[ACPI_MAX_TABLES] __initdata;

/*
 * Replace every non-printable or non-ascii byte in the string
 * with a question mark '?'
 */
static void acpi_tb_fix_string(char *string, size_t length)
{
	while (length && *string) {
		if (!isprint((int)*string)) {
			*string = '?';
		}
		string++;
		length--;
	}
}

/*
 * Copy the table header and ensure that all "string" fields in
 * the header consist of printable characters.
 */
static void
acpi_tb_cleanup_table_header(struct acpi_table_header *out_header,
			     struct acpi_table_header *header)
{

	memcpy(out_header, header, sizeof(struct acpi_table_header));

	acpi_tb_fix_string(out_header->signature, ACPI_NAME_SIZE);
	acpi_tb_fix_string(out_header->oem_id, ACPI_OEM_ID_SIZE);
	acpi_tb_fix_string(out_header->oem_table_id, ACPI_OEM_TABLE_ID_SIZE);
	acpi_tb_fix_string(out_header->asl_compiler_id, ACPI_NAME_SIZE);
}

static void acpi_tb_print_table_header(unsigned long address, struct acpi_table_header *header)
{
	struct acpi_table_header local_header;

	if (ACPI_COMPARE_NAME(header->signature, ACPI_SIG_FACS)) {
		/* FACS only has signature and length fields */
		pr_info("%-4.4s 0x%8.8X%8.8X %06X\n",
			header->signature, ACPI_FORMAT_UINT64(address),
			header->length);
	} else if (!strncmp(header->signature, ACPI_SIG_RSDP, 8)) {

		/* RSDP has no common fields */
		memcpy(local_header.oem_id,
			((struct acpi_table_rsdp *)header)->oem_id,
			ACPI_OEM_ID_SIZE);
		acpi_tb_fix_string(local_header.oem_id, ACPI_OEM_ID_SIZE);

		pr_info("RSDP 0x%8.8X%8.8X %06X (v%.2d %-6.6s)\n",
			ACPI_FORMAT_UINT64(address),
			(((struct acpi_table_rsdp *)header)->revision > 0) ?
			((struct acpi_table_rsdp *)header)->length : 20,
			((struct acpi_table_rsdp *)header)->revision,
			   local_header.oem_id);
	} else {
		/* Standard ACPI table with full common header */
		acpi_tb_cleanup_table_header(&local_header, header);

		pr_info("%-4.4s 0x%8.8X%8.8X"
			   " %06X (v%.2d %-6.6s %-8.8s %08X %-4.4s %08X)\n",
			   local_header.signature, ACPI_FORMAT_UINT64(address),
			   local_header.length, local_header.revision,
			   local_header.oem_id, local_header.oem_table_id,
			   local_header.oem_revision,
			   local_header.asl_compiler_id,
			   local_header.asl_compiler_revision);
	}
}

/*
 * This function is called to parse the
 * Root System Description Table (RSDT or XSDT)
 */
static int acpi_tb_parse_root_table(unsigned long rsdp_address)
{
	struct acpi_table_rsdp *rsdp;

	rsdp = early_ioremap(rsdp_address, sizeof(struct acpi_table_rsdp));
	if (!rsdp)
		return -ENOMEM;

	acpi_tb_print_table_header(rsdp_address, (struct acpi_table_header *)rsdp);

	early_iounmap(rsdp, sizeof(struct acpi_table_rsdp));

	return 0;
}

static u8 acpi_tb_checksum(u8 *buffer, u32 length)
{
	u8 sum = 0;
	u8 *end = buffer + length;

	while (buffer < end) {
		sum = (u8)(sum + *(buffer++));
	}

	return (sum);
}

static int acpi_tb_validate_rsdp(struct acpi_table_rsdp *rsdp)
{
	/*
	 * The signature and checksum must both be correct
	 *
	 * Note: Sometimes there exists more than one RSDP in memory; the valid
	 * RSDP has a valid checksum, all others have an invalid checksum.
	 */
	if (!ACPI_VALIDATE_RSDP_SIG(rsdp->signature))
		return AE_BAD_SIGNATURE;

	/* Check the standard checksum */
	if (acpi_tb_checksum((u8 *) rsdp, ACPI_RSDP_CHECKSUM_LENGTH) != 0)
		return AE_BAD_CHECKSUM;

	/* Check extended checksum if table version >= 2 */
	if ((rsdp->revision >= 2) &&
	    (acpi_tb_checksum((u8 *) rsdp, ACPI_RSDP_XCHECKSUM_LENGTH) != 0)) {
		return AE_BAD_CHECKSUM;
	}
	return 0;
}

/*
 * RETURN:      Pointer to the RSDP if found, otherwise NULL.
 * DESCRIPTION: Search a block of memory for the RSDP signature
 */
static u8 *acpi_scan_memory_for_rsdp(u8 *start_address, u32 length)
{
	int status;
	u8 *mem_rover;
	u8 *end_address;

	end_address = start_address + length;

	/* Search from given start address for the requested length */
	for (mem_rover = start_address; mem_rover < end_address;
	     mem_rover += ACPI_RSDP_SCAN_STEP) {
		/* The RSDP signature and checksum must both be correct */
		status = acpi_tb_validate_rsdp((struct acpi_table_rsdp *)mem_rover);
		if (!status)
			return mem_rover;
	}
	pr_info("RSDP was not found from %p + %#x\n", start_address, length);
	return NULL;
}

static unsigned long acpi_get_root_pointer(void)
{
	u8 *table_ptr;
	u8 *mem_rover;
	u32 physical_address;

	/*
	 * 1) Search EBDA
	 */

	table_ptr = early_ioremap((unsigned long)ACPI_EBDA_PTR_LOCATION, ACPI_EBDA_PTR_LENGTH);
	if (!table_ptr) {
		pr_err("Can not map at 0x%8.8X for length %u\n",
			ACPI_EBDA_PTR_LOCATION, ACPI_EBDA_PTR_LENGTH);
		return 0;
	}

	/* Get the segment base of EBDA area */
	physical_address = (u32)(*(u16 *)table_ptr);
	physical_address <<= 4;
	early_iounmap(table_ptr, ACPI_EBDA_PTR_LENGTH);

	/* EBDA present? */
	if (physical_address > 0x400) {
		table_ptr = early_ioremap((unsigned long)physical_address, ACPI_EBDA_WINDOW_SIZE);
		if (!table_ptr) {
			pr_err("Can not map at 0x%8.8X for len %u\n",
				physical_address, ACPI_EBDA_WINDOW_SIZE);
			return 0;
		}

		mem_rover = acpi_scan_memory_for_rsdp(table_ptr, ACPI_EBDA_WINDOW_SIZE);
		early_iounmap(table_ptr, ACPI_EBDA_WINDOW_SIZE);
		if (mem_rover) {
			physical_address += (u32)(mem_rover - table_ptr);
			return physical_address;
		}
	}

	/*
	 * 2) Search upper memory: 16-byte boundaries in E0000h-FFFFFh
	 */
	table_ptr = early_ioremap((unsigned long)ACPI_HI_RSDP_WINDOW_BASE, ACPI_HI_RSDP_WINDOW_SIZE);
	if (!table_ptr) {
		pr_err("Can not map at 0x%8.8X for length %u\n",
			ACPI_HI_RSDP_WINDOW_BASE, ACPI_HI_RSDP_WINDOW_SIZE);
		return 0;
	}

	mem_rover = acpi_scan_memory_for_rsdp(table_ptr, ACPI_HI_RSDP_WINDOW_SIZE);
	early_iounmap(table_ptr, ACPI_HI_RSDP_WINDOW_SIZE);
	if (mem_rover) {
		physical_address = (u32)(ACPI_HI_RSDP_WINDOW_BASE +
		     (u32)(mem_rover - table_ptr));
		return physical_address;
	}

	pr_err("A valid RSDP was not found!\n");
	return 0;
}

void __init acpi_table_init(void)
{
	int ret;
	unsigned long rsdp_address;

	rsdp_address = acpi_get_root_pointer();
	if (!rsdp_address)
		return;

	/*
	 * Get the root table (RSDT or XSDT)
	 * and extract all entries to the local Root Table Array.
	 *
	 * This array contains the information of the RSDT/XSDT
	 * in a common, more useable format.
	 */
	ret = acpi_tb_parse_root_table(rsdp_address);
	if (ret)
		pr_err("fail to parse rsdp\n");
}
