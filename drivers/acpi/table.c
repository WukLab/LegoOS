/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
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

#include "internal.h"

u32 acpi_gbl_fadt_index;

/**
 * acpi_parse_entries_array - for each proc_num find a suitable subtable
 *
 * @id: table id (for debugging purposes)
 * @table_size: single entry size
 * @table_header: where does the table start?
 * @proc: array of acpi_subtable_proc struct containing entry id
 *        and associated handler with it
 * @proc_num: how big proc is?
 * @max_entries: how many entries can we process?
 *
 * For each proc_num find a subtable with proc->id and run proc->handler
 * on it. Assumption is that there's only single handler for particular
 * entry id.
 *
 * On success returns sum of all matching entries for all proc handlers.
 * Otherwise, -ENODEV or -EINVAL is returned.
 */
static int __init
acpi_parse_entries_array(char *id, unsigned long table_size,
		struct acpi_table_header *table_header,
		struct acpi_subtable_proc *proc, int proc_num,
		unsigned int max_entries)
{
	struct acpi_subtable_header *entry;
	unsigned long table_end;
	int count = 0;
	int errs = 0;
	int i;

	if (!id)
		return -EINVAL;

	if (!table_size)
		return -EINVAL;

	if (!table_header) {
		pr_warn("%4.4s not present\n", id);
		return -ENODEV;
	}

	table_end = (unsigned long)table_header + table_header->length;

	/* Parse all entries looking for a match. */

	entry = (struct acpi_subtable_header *)
	    ((unsigned long)table_header + table_size);

	while (((unsigned long)entry) + sizeof(struct acpi_subtable_header) <
	       table_end) {
		if (max_entries && count >= max_entries)
			break;

		for (i = 0; i < proc_num; i++) {
			if (entry->type != proc[i].id)
				continue;
			if (!proc[i].handler ||
			     (!errs && proc[i].handler(entry, table_end))) {
				errs++;
				continue;
			}

			proc[i].count++;
			break;
		}
		if (i != proc_num)
			count++;

		/*
		 * If entry->length is 0, break from this loop to avoid
		 * infinite loop.
		 */
		if (entry->length == 0) {
			pr_err("[%4.4s:0x%02x] Invalid zero length\n", id, proc->id);
			return -EINVAL;
		}

		entry = (struct acpi_subtable_header *)
		    ((unsigned long)entry + entry->length);
	}

	if (max_entries && count > max_entries) {
		pr_warn("[%4.4s:0x%02x] found the maximum %i entries\n",
			id, proc->id, count);
	}

	return errs ? -EINVAL : count;
}

int __init
acpi_table_parse_entries_array(char *id,
			 unsigned long table_size,
			 struct acpi_subtable_proc *proc, int proc_num,
			 unsigned int max_entries)
{
	struct acpi_table_header *table_header = NULL;
	int count;
	u32 instance = 0;

	if (!id)
		return -EINVAL;

	acpi_get_table(id, instance, &table_header);
	if (!table_header) {
		pr_warn("%4.4s not present\n", id);
		return -ENODEV;
	}

	count = acpi_parse_entries_array(id, table_size, table_header,
			proc, proc_num, max_entries);

	acpi_put_table(table_header);
	return count;
}

int __init
acpi_table_parse_entries(char *id,
			unsigned long table_size,
			int entry_id,
			acpi_tbl_entry_handler handler,
			unsigned int max_entries)
{
	struct acpi_subtable_proc proc = {
		.id		= entry_id,
		.handler	= handler,
	};

	return acpi_table_parse_entries_array(id, table_size, &proc, 1,
						max_entries);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_get_table
 *
 * PARAMETERS:  table_desc          - Table descriptor
 *              out_table           - Where the pointer to the table is returned
 *
 * RETURN:      Status and pointer to the requested table
 *
 * DESCRIPTION: Increase a reference to a table descriptor and return the
 *              validated table pointer.
 *              If the table descriptor is an entry of the root table list,
 *              this API must be invoked with ACPI_MTX_TABLES acquired.
 *
 ******************************************************************************/
int acpi_tb_get_table(struct acpi_table_desc *table_desc,
		      struct acpi_table_header **out_table)
{
	int status;

	if (table_desc->validation_count == 0) {

		/* Table need to be "VALIDATED" */
		status = acpi_tb_validate_table(table_desc);
		if (status)
			return status;
	}

	table_desc->validation_count++;

	*out_table = table_desc->pointer;

	return 0;
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_put_table
 *
 * PARAMETERS:  table_desc          - Table descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Decrease a reference to a table descriptor and release the
 *              validated table pointer if no references.
 *              If the table descriptor is an entry of the root table list,
 *              this API must be invoked with ACPI_MTX_TABLES acquired.
 *
 ******************************************************************************/
void acpi_tb_put_table(struct acpi_table_desc *table_desc)
{

	if (table_desc->validation_count == 0) {
		pr_err("Table %p, Validation count is zero before decrement\n", table_desc);
		return;
	}
	table_desc->validation_count--;

	if (table_desc->validation_count == 0) {
		/* Table need to be "INVALIDATED" */
		acpi_tb_invalidate_table(table_desc);
	}
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_get_table
 *
 * PARAMETERS:  signature           - ACPI signature of needed table
 *              instance            - Which instance (for SSDTs)
 *              out_table           - Where the pointer to the table is returned
 *
 * RETURN:      Status and pointer to the requested table
 *
 * DESCRIPTION: Finds and verifies an ACPI table. Table must be in the
 *              RSDT/XSDT.
 *              Note that an early stage acpi_get_table() call must be paired
 *              with an early stage acpi_put_table() call. otherwise the table
 *              pointer mapped by the early stage mapping implementation may be
 *              erroneously unmapped by the late stage unmapping implementation
 *              in an acpi_put_table() invoked during the late stage.
 *
 ******************************************************************************/
int acpi_get_table(char *signature, u32 instance, struct acpi_table_header ** out_table)
{
	u32 i;
	u32 j;
	int status = 0;
	struct acpi_table_desc *table_desc;

	/* Parameter validation */
	if (!signature || !out_table)
		return -EINVAL;

	/*
	 * Note that the following line is required by some OSPMs, they only
	 * check if the returned table is NULL instead of the returned status
	 * to determined if this function is succeeded.
	 */
	*out_table = NULL;

	/* Walk the root table list */
	for (i = 0, j = 0; i < nr_acpi_tables; i++) {
		table_desc = &acpi_tables[i];

		if (!ACPI_COMPARE_NAME(&table_desc->signature, signature)) {
			continue;
		}

		if (++j < instance) {
			continue;
		}

		status = acpi_tb_get_table(table_desc, out_table);
		break;
	}

	return status;
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_put_table
 *
 * PARAMETERS:  table               - The pointer to the table
 *
 * RETURN:      None
 *
 * DESCRIPTION: Release a table returned by acpi_get_table() and its clones.
 *              Note that it is not safe if this function was invoked after an
 *              uninstallation happened to the original table descriptor.
 *              Currently there is no OSPMs' requirement to handle such
 *              situations.
 *
 ******************************************************************************/
void acpi_put_table(struct acpi_table_header *table)
{
	u32 i;
	struct acpi_table_desc *table_desc;

	/* Walk the root table list */
	for (i = 0; i < nr_acpi_tables; i++) {
		table_desc = &acpi_tables[i];

		if (table_desc->pointer != table) {
			continue;
		}

		acpi_tb_put_table(table_desc);
		break;
	}
}

/**
 * acpi_table_parse - find table with @id, run @handler on it
 * @id: table id to find
 * @handler: handler to run
 *
 * Scan the ACPI System Descriptor Table (STD) for a table matching @id,
 * run @handler on it.
 *
 * Return 0 if table found, -errno if not.
 */
int __init acpi_parse_table(char *id, acpi_tbl_table_handler handler)
{
	struct acpi_table_header *table = NULL;

	if (!id || !handler)
		return -EINVAL;

	acpi_get_table(id, 0, &table);

	if (table) {
		handler(table);
		acpi_put_table(table);
		return 0;
	} else
		return -ENODEV;
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_get_root_table_entry
 *
 * PARAMETERS:  table_entry         - Pointer to the RSDT/XSDT table entry
 *              table_entry_size    - sizeof 32 or 64 (RSDT or XSDT)
 *
 * RETURN:      Physical address extracted from the root table
 *
 * DESCRIPTION: Get one root table entry. Handles 32-bit and 64-bit cases on
 *              both 32-bit and 64-bit platforms
 *
 * NOTE:        acpi_physical_address is 32-bit on 32-bit platforms, 64-bit on
 *              64-bit platforms.
 *
 ******************************************************************************/
static acpi_physical_address
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
		return ((acpi_physical_address)
			(*ACPI_CAST_PTR(u32, table_entry)));
	} else {
		/*
		 * 32-bit platform, XSDT: Truncate 64-bit to 32-bit and return
		 * 64-bit platform, XSDT: Move (unaligned) 64-bit to local,
		 *  return 64-bit
		 */
		ACPI_MOVE_64_TO_64(&address64, table_entry);
		return ((acpi_physical_address)(address64));
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

void __init
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
		       ACPI_CAST_PTR(struct acpi_table_rsdp, header)->oem_id,
		       ACPI_OEM_ID_SIZE);
		acpi_tb_fix_string(local_header.oem_id, ACPI_OEM_ID_SIZE);

		pr_info("RSDP 0x%8.8X%8.8X %06X (v%.2d %-6.6s)\n",
			   ACPI_FORMAT_UINT64(address),
			   (ACPI_CAST_PTR(struct acpi_table_rsdp, header)->
			    revision >
			    0) ? ACPI_CAST_PTR(struct acpi_table_rsdp,
					       header)->length : 20,
			   ACPI_CAST_PTR(struct acpi_table_rsdp,
					 header)->revision,
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

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_acquire_table
 *
 * PARAMETERS:  table_desc          - Table descriptor
 *              table_ptr           - Where table is returned
 *              table_length        - Where table length is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Acquire an ACPI table. It can be used for tables not
 *              maintained in the acpi_gbl_root_table_list.
 *
 ******************************************************************************/
static __init int
acpi_tb_acquire_table(struct acpi_table_desc *table_desc,
		      struct acpi_table_header **table_ptr,
		      u32 *table_length)
{
	struct acpi_table_header *table = NULL;

	table = early_ioremap(table_desc->address, table_desc->length);

	/* Table is not valid yet */
	if (!table)
		return -ENOMEM;

	/* Fill the return values */
	*table_ptr = table;
	*table_length = table_desc->length;

	return 0;
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_release_table
 *
 * PARAMETERS:  table               - Pointer for the table
 *              table_length        - Length for the table
 *
 * RETURN:      None
 *
 * DESCRIPTION: Release a table. The inverse of acpi_tb_acquire_table().
 *
 ******************************************************************************/
static __init void
acpi_tb_release_table(struct acpi_table_header *table,
		      u32 table_length)
{
	early_iounmap(table, table_length);
}

/******************************************************************************
 *
 * FUNCTION:    acpi_tb_validate_table
 *
 * PARAMETERS:  table_desc          - Table descriptor
 *
 * RETURN:      Status
 *
 * DESCRIPTION: This function is called to validate the table, the returned
 *              table descriptor is in "VALIDATED" state.
 *
 *****************************************************************************/
int acpi_tb_validate_table(struct acpi_table_desc *table_desc)
{
	int ret = 0;

	/* Validate the table if necessary */
	if (!table_desc->pointer) {
		ret = acpi_tb_acquire_table(table_desc, &table_desc->pointer,
					    &table_desc->length);
		if (!table_desc->pointer)
			ret = -ENOMEM;
	}
	return ret;
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_invalidate_table
 *
 * PARAMETERS:  table_desc          - Table descriptor
 *
 * RETURN:      None
 *
 * DESCRIPTION: Invalidate one internal ACPI table, this is the inverse of
 *              acpi_tb_validate_table().
 *
 ******************************************************************************/
void acpi_tb_invalidate_table(struct acpi_table_desc *table_desc)
{

	/* Table must be validated */
	if (!table_desc->pointer)
		return;

	acpi_tb_release_table(table_desc->pointer, table_desc->length);
	table_desc->pointer = NULL;
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_init_table_descriptor
 *
 * PARAMETERS:  table_desc              - Table descriptor
 *              address                 - Physical address of the table
 *              table                   - Pointer to the table
 *
 * RETURN:      None
 *
 * DESCRIPTION: Initialize a new table descriptor
 *
 ******************************************************************************/
void
acpi_tb_init_table_descriptor(struct acpi_table_desc *table_desc,
			      u64 address, struct acpi_table_header *table)
{

	/*
	 * Initialize the table descriptor. Set the pointer to NULL, since the
	 * table is not fully mapped at this time.
	 */
	memset(table_desc, 0, sizeof(struct acpi_table_desc));
	table_desc->address = address;
	table_desc->length = table->length;
	ACPI_MOVE_32_TO_32(table_desc->signature.ascii, table->signature);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_acquire_temp_table
 *
 * PARAMETERS:  table_desc          - Table descriptor to be acquired
 *              address             - Address of the table
 *
 * RETURN:      Status
 *
 * DESCRIPTION: This function validates the table header to obtain the length
 *              of a table and fills the table descriptor to make its state as
 *              "INSTALLED". Such a table descriptor is only used for verified
 *              installation.
 *
 ******************************************************************************/
static __init int
acpi_tb_acquire_temp_table(struct acpi_table_desc *table_desc, u64 address)
{
	struct acpi_table_header *table_header;

	/* Get the length of the full table from the header */
	table_header = early_ioremap(address, sizeof(struct acpi_table_header));
	if (!table_header)
		return -ENOMEM;

	acpi_tb_init_table_descriptor(table_desc, address, table_header);
	early_iounmap(table_header, sizeof(struct acpi_table_header));

	return 0;
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_release_temp_table
 *
 * PARAMETERS:  table_desc          - Table descriptor to be released
 *
 * RETURN:      Status
 *
 * DESCRIPTION: The inverse of acpi_tb_acquire_temp_table().
 *
 *****************************************************************************/
static __init void
acpi_tb_release_temp_table(struct acpi_table_desc *table_desc)
{

	/*
	 * Note that the .Address is maintained by the callers of
	 * acpi_tb_acquire_temp_table(), thus do not invoke acpi_tb_uninstall_table()
	 * where .Address will be freed.
	 */
	acpi_tb_invalidate_table(table_desc);
}

/******************************************************************************
 *
 * FUNCTION:    acpi_tb_validate_temp_table
 *
 * PARAMETERS:  table_desc          - Table descriptor
 *
 * RETURN:      Status
 *
 * DESCRIPTION: This function is called to validate the table, the returned
 *              table descriptor is in "VALIDATED" state.
 *
 *****************************************************************************/
static __init int
acpi_tb_validate_temp_table(struct acpi_table_desc *table_desc)
{

	if (!table_desc->pointer) {
		/*
		 * Only validates the header of the table.
		 * Note that Length contains the size of the mapping after invoking
		 * this work around, this value is required by
		 * acpi_tb_release_temp_table().
		 * We can do this because in acpi_init_table_descriptor(), the Length
		 * field of the installed descriptor is filled with the actual
		 * table length obtaining from the table header.
		 */
		table_desc->length = sizeof(struct acpi_table_header);
	}

	return (acpi_tb_validate_table(table_desc));
}

/******************************************************************************
 *
 * FUNCTION:    acpi_tb_verify_temp_table
 *
 * PARAMETERS:  table_desc          - Table descriptor
 *              signature           - Table signature to verify
 *
 * RETURN:      Status
 *
 * DESCRIPTION: This function is called to validate and verify the table, the
 *              returned table descriptor is in "VALIDATED" state.
 *
 *****************************************************************************/
static __init int
acpi_tb_verify_temp_table(struct acpi_table_desc *table_desc, char *signature)
{
	int ret = 0;

	/* Validate the table */
	ret = acpi_tb_validate_temp_table(table_desc);
	if (ret)
		return -ENOMEM;

	/* If a particular signature is expected (DSDT/FACS), it must match */
	if (signature && !ACPI_COMPARE_NAME(&table_desc->signature, signature)) {
		pr_err("Invalid signature 0x%X for ACPI table, expected [%s]",
			table_desc->signature.integer, signature);
		ret = -EFAULT;
		goto invalidate_and_exit;
	}
	return 0;

invalidate_and_exit:
	acpi_tb_invalidate_table(table_desc);
	return ret;
}

static int __init
acpi_tb_install_standard_table(u64 address, bool reload, bool override,
				u32 *table_index)
{
	int ret = 0;
	struct acpi_table_desc desc;

	/* Acquire a temporary table descriptor for validation */
	ret = acpi_tb_acquire_temp_table(&desc, address);
	if (ret) {
		pr_err("Could not acquire table length at %8.8X%8.8X\n",
			ACPI_FORMAT_UINT64(address));
		return -ENOMEM;
	}

	/* Validate and verify a table before installation */
	ret = acpi_tb_verify_temp_table(&desc, NULL);
	if (ret)
		goto release_and_exit;

	/* Add the table to the global root table list */
	acpi_tb_install_table_with_override(&desc, override, table_index);

release_and_exit:
	/* Release the temporary table descriptor */
	acpi_tb_release_temp_table(&desc);
	return ret;
}

/*
 * PARAMETERS:  rsdp                    - Pointer to the RSDP
 *
 * DESCRIPTION: This function is called to parse the Root System Description
 *              Table (RSDT or XSDT)
 *
 * NOTE:        Tables are mapped (not copied) for efficiency. The FACS must
 *              be mapped and cannot be copied because it contains the actual
 *              memory location of the ACPI Global Lock.
 */
static int __init acpi_tb_parse_root_table(u64 rsdp_address)
{
	int i, ret;
	u8 *table_entry;
	u32 length, table_count;
	u32 table_entry_size;
	u32 table_index;
	u64 address;
	struct acpi_table_rsdp *rsdp;
	struct acpi_table_header *table;

	/* Map the entire RSDP and extract the address of the RSDT or XSDT */
	rsdp = early_ioremap(rsdp_address, sizeof(struct acpi_table_rsdp));
	if (!rsdp) {
		pr_err("Unable to ioremap entire RSDP\n");
		return -ENOMEM;
	}

	acpi_tb_print_table_header(rsdp_address, (struct acpi_table_header *)rsdp);

	/* Use XSDT if present and not overridden. Otherwise, use RSDT */
	if ((rsdp->revision > 1) && rsdp->xsdt_physical_address) {
		/*
		 * RSDP contains an XSDT (64-bit physical addresses). We must use
		 * the XSDT if the revision is > 1 and the XSDT pointer is present,
		 * as per the ACPI specification.
		 */
		address = (u64)rsdp->xsdt_physical_address;
		table_entry_size = ACPI_XSDT_ENTRY_SIZE;
	} else {
		/* Root table is an RSDT (32-bit physical addresses) */
		address = (u64)rsdp->rsdt_physical_address;
		table_entry_size = ACPI_RSDT_ENTRY_SIZE;
	}
	early_iounmap(rsdp, sizeof(struct acpi_table_rsdp));

	/*
	 * Map the *header* of RSDT/XSDT table
	 * to get the full table length
	 */
	table = early_ioremap(address, sizeof(struct acpi_table_header));
	if (!table)
		return -ENOMEM;
	acpi_tb_print_table_header(address, table);

	/*
	 * Validate length of the table, and map entire table.
	 * Minimum length table must contain at least one entry.
	 */
	length = table->length;
	early_iounmap(table, sizeof(struct acpi_table_header));

	/* Minimum length table must contain at least one entry */
	if (length < (sizeof(struct acpi_table_header) + table_entry_size)) {
		pr_err("Invalid table length 0x%X in RSDT/XSDT", length);
		return -EFAULT;
	}

	/* Map the *whole* RSDT/XSDT table */
	table = early_ioremap(address, length);
	if (!table)
		return -ENOMEM;

	table_count = (u32)((table->length - sizeof(struct acpi_table_header)) /
			    table_entry_size);
	table_entry = ACPI_ADD_PTR(u8, table, sizeof(struct acpi_table_header));

	/*
	 * Iterate all ACPI tables and install them
	 * in internal acpi_tables[] descriptor array
	 */
	for (i = 0; i < table_count; i++) {
		/* Get table physical address (32-bit for RSDT, 64-bit for XSDT) */
		address = acpi_tb_get_root_table_entry(table_entry, table_entry_size);

		/* Skip NULL entries in RSDT/XSDT */
		if (!address)
			goto next_table;

		ret = acpi_tb_install_standard_table(address,
					false, true, &table_index);
		if (!ret && ACPI_COMPARE_NAME(&acpi_tables[table_index].signature,
					      ACPI_SIG_FADT)) {
			acpi_gbl_fadt_index = table_index;
			acpi_tb_parse_fadt();
		}
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
	pr_debug("RSDP was not found from %p + %#x\n", start_address, length);
	return NULL;
}

/*
 * Search lower 1Mbyte of memory for the root system descriptor
 * pointer structure. If it is found, set *RSDP to point to it.
 *
 * The RSDP must be either in the first 1K of the Extended
 * BIOS Data Area or between E0000 and FFFFF (From ACPI Spec.)
 * Only a 32-bit physical address is necessary.
 */
static __init u64 acpi_os_get_root_pointer(void)
{
	u8 *table_ptr;
	u8 *mem_rover;
	u32 physical_address;
	u64 table_address;

	/*
	 * 1) Search EBDA
	 */

	table_ptr = early_ioremap((u64)ACPI_EBDA_PTR_LOCATION, ACPI_EBDA_PTR_LENGTH);
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
		table_ptr = early_ioremap((u64)physical_address, ACPI_EBDA_WINDOW_SIZE);
		if (!table_ptr) {
			pr_err("Can not map at 0x%8.8X for len %u\n",
				physical_address, ACPI_EBDA_WINDOW_SIZE);
			return 0;
		}

		mem_rover = acpi_tb_scan_memory_for_rsdp(table_ptr, ACPI_EBDA_WINDOW_SIZE);
		early_iounmap(table_ptr, ACPI_EBDA_WINDOW_SIZE);
		if (mem_rover) {
			physical_address += (u32)(mem_rover - table_ptr);
			table_address = (u64)physical_address;
			return table_address;
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
		table_address = (u64)physical_address;
		return table_address;
	}
	return 0;
}

/*
 * acpi_table_init()
 *
 * find RSDP, find and checksum SDT/XSDT.
 * checksum all tables, print SDT/XSDT
 */
void __init acpi_table_init(void)
{
	int ret;
	unsigned long rsdp_address;

	/* Get the address of the RSDP */
	rsdp_address = acpi_os_get_root_pointer();
	if (!rsdp_address) {
		panic("ACPI: fail to find RSDP");
		return;
	}

	/*
	 * Get the root table (RSDT or XSDT)
	 * and extract all entries to the local Root Table Array.
	 *
	 * This array contains the information of the RSDT/XSDT
	 * in a common, more useable format.
	 */
	ret = acpi_tb_parse_root_table(rsdp_address);
	if (ret)
		panic("ACPI: fail to parse root table");
}
