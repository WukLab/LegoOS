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

#define ACPI_MAX_TABLES 128
static int nr_acpi_tables = 0;
static struct acpi_table_desc acpi_tables[ACPI_MAX_TABLES] __initdata;

/**
 * acpi_parse_table
 * @signature:
 * @handler:
 */
int __init acpi_parse_table(char *signature, acpi_table_handler handler)
{
	struct acpi_table_desc *desc;
	struct acpi_table_header *header;
	int i;

	if (!signature || !handler)
		return -EINVAL;

	header = NULL;
	for (i = 0; i < nr_acpi_tables; i++) {
		desc = &acpi_tables[i];
		if (!strncmp(desc->signature.ascii, signature, 4)) {
			header = desc->pointer;
			break;
		}
	}

	if (header)
		handler(header);
	else
		return -ENODEV;

	return 0;
}

static inline u64 __init
acpi_tb_get_root_table_entry(u8 *table_entry, u32 table_entry_size)
{
	u64 address64;

	/*
	 * Get the table physical address (32-bit for RSDT, 64-bit for XSDT):
	 * Note: Addresses are 32-bit aligned (not 64) in both RSDT and XSDT
	 */
	if (table_entry_size == ACPI_RSDT_ENTRY_SIZE) {
		/*
		 * 32-bit platform, RSDT: Return 32-bit table entry
		 * 64-bit platform, RSDT: Expand 32-bit to 64-bit and return
		 */
		return ((u64)(*ACPI_CAST_PTR(u32, table_entry)));
	} else {
		/*
		 * 32-bit platform, XSDT: Truncate 64-bit to 32-bit and return
		 * 64-bit platform, XSDT: Move (unaligned) 64-bit to local,
		 *  return 64-bit
		 */
		address64 = *((u64 *)table_entry);
		return ((u64)(address64));
	}
}

/*
 * Replace every non-printable or non-ascii byte in the string
 * with a question mark '?'
 */
static void __init acpi_tb_fix_string(char *string, size_t length)
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
static void __init
acpi_tb_cleanup_table_header(struct acpi_table_header *out_header,
			     struct acpi_table_header *header)
{
	memcpy(out_header, header, sizeof(struct acpi_table_header));

	acpi_tb_fix_string(out_header->signature, ACPI_NAME_SIZE);
	acpi_tb_fix_string(out_header->oem_id, ACPI_OEM_ID_SIZE);
	acpi_tb_fix_string(out_header->oem_table_id, ACPI_OEM_TABLE_ID_SIZE);
	acpi_tb_fix_string(out_header->asl_compiler_id, ACPI_NAME_SIZE);
}

static void __init
acpi_tb_print_table_header(unsigned long address, struct acpi_table_header *header)
{
	struct acpi_table_header local_header;

	if (ACPI_COMPARE_NAME(header->signature, ACPI_SIG_FACS)) {
		/* FACS only has signature and length fields */
		pr_info("%-4.4s 0x%8.8X%8.8X %06X\n",
			header->signature, ACPI_FORMAT_UINT64(address),
			header->length);
	} else if (ACPI_VALIDATE_RSDP_SIG(header->signature)) {
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
 * Map the whole table and construct a internal table descriptor
 * which will be installed into the acpi_tables[] array.
 */
static int __init acpi_tb_install(unsigned long address)
{
	struct acpi_table_header *header;
	struct acpi_table_desc desc;

	/* Map header */
	header = early_ioremap(address, sizeof(*header));
	if (!header)
		return -ENOMEM;

	acpi_tb_print_table_header(address, header);

	memset(&desc, 0, sizeof(desc));
	desc.address = address;
	desc.length = header->length;
	memcpy(&desc.signature, header->signature, ACPI_NAME_SIZE);

	/* Unmap header */
	early_iounmap(header, sizeof(*header));

	/* Map whole table */
	header = early_ioremap(address, desc.length);
	if (!header)
		return -ENOMEM;

	desc.pointer = header;
	acpi_tables[nr_acpi_tables++] = desc;
	BUG_ON(nr_acpi_tables > ACPI_MAX_TABLES);

	return 0;
}

/*
 * This function is called to parse the
 * Root System Description Table (RSDT or XSDT)
 */
static int __init acpi_tb_parse_root_table(unsigned long rsdp_address)
{
	int i;
	u8 *table_entry;
	u32 length, table_count;
	u32 table_entry_size;
	u64 address;
	struct acpi_table_rsdp *rsdp;
	struct acpi_table_header *table;

	rsdp = early_ioremap(rsdp_address, sizeof(struct acpi_table_rsdp));
	if (!rsdp)
		return -ENOMEM;

	acpi_tb_print_table_header(rsdp_address, (struct acpi_table_header *)rsdp);

	if ((rsdp->revision > 1) && rsdp->xsdt_physical_address) {
		/*
		 * RSDP contains an XSDT (64-bit physical addresses). We must use
		 * the XSDT if the revision is > 1 and the XSDT pointer is present,
		 * as per the ACPI specification.
		 */
		address = rsdp->xsdt_physical_address;
		table_entry_size = ACPI_XSDT_ENTRY_SIZE;
	} else {
		/* Root table is an RSDT (32-bit physical addresses) */
		address = (u64)rsdp->rsdt_physical_address;
		table_entry_size = ACPI_RSDT_ENTRY_SIZE;
	}
	early_iounmap(rsdp, sizeof(struct acpi_table_rsdp));

	/*
	 * Map the RSDT/XSDT table header to get the full table length
	 * Validate length of the table, and map entire table.
	 */
	table = early_ioremap(address, sizeof(struct acpi_table_header));
	if (!table)
		return -ENOMEM;
	acpi_tb_print_table_header(address, table);
	length = table->length;
	early_iounmap(table, sizeof(struct acpi_table_header));

	/* Minimum length table must contain at least one entry */
	if (length < (sizeof(struct acpi_table_header) + table_entry_size)) {
		pr_err("Invalid table length 0x%X in RSDT/XSDT", length);
		return -EFAULT;
	}

	/* Remap the whole RSDT/XSDT table */
	table = early_ioremap(address, length);
	if (!table)
		return -ENOMEM;

	table_count = (u32)((table->length - sizeof(struct acpi_table_header)) /
				table_entry_size);
	table_entry = (u8 *)((u8 *)table + sizeof(struct acpi_table_header));

	/*
	 * Iterate all ACPI tables and install them
	 * in internal acpi_tables[] descriptor array
	 */
	for (i = 0; i < table_count; i++) {
		unsigned long pa;

		/* Get table physical address (32-bit for RSDT, 64-bit for XSDT) */
		pa = acpi_tb_get_root_table_entry(table_entry, table_entry_size);
		if (!pa)
			goto next_table;

		if (acpi_tb_install(pa))
			return -EFAULT;
next_table:
		table_entry += table_entry_size;
	}

	/* Unmap the whole RSDT/XSDT table */
	early_iounmap(table, length);

	return 0;
}

static inline u8 acpi_tb_checksum(u8 *buffer, u32 length)
{
	u8 sum = 0;
	u8 *end = buffer + length;

	while (buffer < end) {
		sum = (u8)(sum + *(buffer++));
	}

	return (sum);
}

static int __init acpi_tb_validate_rsdp(struct acpi_table_rsdp *rsdp)
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
static __init u8 *acpi_tb_scan_memory_for_rsdp(u8 *start_address, u32 length)
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

static __init unsigned long acpi_tb_get_root_pointer(void)
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

		mem_rover = acpi_tb_scan_memory_for_rsdp(table_ptr, ACPI_EBDA_WINDOW_SIZE);
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

	mem_rover = acpi_tb_scan_memory_for_rsdp(table_ptr, ACPI_HI_RSDP_WINDOW_SIZE);
	early_iounmap(table_ptr, ACPI_HI_RSDP_WINDOW_SIZE);
	if (mem_rover) {
		physical_address = (u32)(ACPI_HI_RSDP_WINDOW_BASE +
		     (u32)(mem_rover - table_ptr));
		return physical_address;
	}

	pr_err("A valid RSDP was not found!\n");
	return 0;
}

void __init acpi_unmap_tables(void)
{
	int i;
	struct acpi_table_desc *desc;

	for (i = 0; i < nr_acpi_tables; i++) {
		desc = &acpi_tables[i];
		early_iounmap(desc->pointer, desc->length);
	}
}

void __init acpi_table_init(void)
{
	int ret;
	unsigned long rsdp_address;

	rsdp_address = acpi_tb_get_root_pointer();
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
