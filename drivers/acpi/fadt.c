/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define pr_fmt(fmt) "ACPI FADT: " fmt

#include <lego/acpi.h>
#include <lego/string.h>
#include <lego/kernel.h>

#include "internal.h"

/*
 * acpi_gbl_FADT is a local copy of the FADT.
 * converted to a common format.
 */
struct acpi_table_fadt acpi_gbl_FADT;

#define ACPI_FADT_INFO_ENTRIES	(sizeof (fadt_info_table) / sizeof (struct acpi_fadt_info))

/*
 * ACPI 5.0 introduces the concept of a "reduced hardware platform", meaning
 * that the ACPI hardware is no longer required. A flag in the FADT indicates
 * a reduced HW machine, and that flag is duplicated here for convenience.
 */
u8 acpi_gbl_reduced_hardware = false;

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_select_address
 *
 * PARAMETERS:  register_name       - ASCII name of the ACPI register
 *              address32           - 32-bit address of the register
 *              address64           - 64-bit address of the register
 *
 * RETURN:      The resolved 64-bit address
 *
 * DESCRIPTION: Select between 32-bit and 64-bit versions of addresses within
 *              the FADT. Used for the FACS and DSDT addresses.
 *
 * NOTES:
 *
 * Check for FACS and DSDT address mismatches. An address mismatch between
 * the 32-bit and 64-bit address fields (FIRMWARE_CTRL/X_FIRMWARE_CTRL and
 * DSDT/X_DSDT) could be a corrupted address field or it might indicate
 * the presence of two FACS or two DSDT tables.
 *
 * November 2013:
 * By default, as per the ACPICA specification, a valid 64-bit address is
 * used regardless of the value of the 32-bit address. However, this
 * behavior can be overridden via the acpi_gbl_use32_bit_fadt_addresses flag.
 *
 ******************************************************************************/
static u64 __init
acpi_tb_select_address(char *register_name, u32 address32, u64 address64)
{

	if (!address64) {

		/* 64-bit address is zero, use 32-bit address */

		return ((u64)address32);
	}

	if (address32 && (address64 != (u64)address32)) {
		/* Address mismatch between 32-bit and 64-bit versions */
		pr_warn( "32/64X %s address mismatch in FADT: "
			   "0x%8.8X/0x%8.8X%8.8X, using %u-bit address",
			   register_name, address32,
			   ACPI_FORMAT_UINT64(address64), 64);
	}

	/* Default is to use the 64-bit address */
	return (address64);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_convert_fadt
 *
 * PARAMETERS:  none - acpi_gbl_FADT is used.
 *
 * RETURN:      None
 *
 * DESCRIPTION: Converts all versions of the FADT to a common internal format.
 *              Expand 32-bit addresses to 64-bit as necessary. Also validate
 *              important fields within the FADT.
 *
 * NOTE:        acpi_gbl_FADT must be of size (struct acpi_table_fadt), and must
 *              contain a copy of the actual BIOS-provided FADT.
 *
 * Notes on 64-bit register addresses:
 *
 * After this FADT conversion, later ACPICA code will only use the 64-bit "X"
 * fields of the FADT for all ACPI register addresses.
 *
 * The 64-bit X fields are optional extensions to the original 32-bit FADT
 * V1.0 fields. Even if they are present in the FADT, they are optional and
 * are unused if the BIOS sets them to zero. Therefore, we must copy/expand
 * 32-bit V1.0 fields to the 64-bit X fields if the the 64-bit X field is
 * originally zero.
 *
 * For ACPI 1.0 FADTs (that contain no 64-bit addresses), all 32-bit address
 * fields are expanded to the corresponding 64-bit X fields in the internal
 * common FADT.
 *
 * For ACPI 2.0+ FADTs, all valid (non-zero) 32-bit address fields are expanded
 * to the corresponding 64-bit X fields, if the 64-bit field is originally
 * zero. Adhering to the ACPI specification, we completely ignore the 32-bit
 * field if the 64-bit field is valid, regardless of whether the host OS is
 * 32-bit or 64-bit.
 *
 * Possible additional checks:
 *  (acpi_gbl_FADT.pm1_event_length >= 4)
 *  (acpi_gbl_FADT.pm1_control_length >= 2)
 *  (acpi_gbl_FADT.pm_timer_length >= 4)
 *  Gpe block lengths must be multiple of 2
 *
 ******************************************************************************/
static void __init acpi_tb_convert_fadt(void)
{
	/*
	 * For ACPI 1.0 FADTs (revision 1 or 2), ensure that reserved fields which
	 * should be zero are indeed zero. This will workaround BIOSs that
	 * inadvertently place values in these fields.
	 *
	 * The ACPI 1.0 reserved fields that will be zeroed are the bytes located
	 * at offset 45, 55, 95, and the word located at offset 109, 110.
	 *
	 * Note: The FADT revision value is unreliable. Only the length can be
	 * trusted.
	 */
	if (acpi_gbl_FADT.header.length <= ACPI_FADT_V2_SIZE) {
		acpi_gbl_FADT.preferred_profile = 0;
		acpi_gbl_FADT.pstate_control = 0;
		acpi_gbl_FADT.cst_control = 0;
		acpi_gbl_FADT.boot_flags = 0;
	}

	/*
	 * Now we can update the local FADT length to the length of the
	 * current FADT version as defined by the ACPI specification.
	 * Thus, we will have a common FADT internally.
	 */
	acpi_gbl_FADT.header.length = sizeof(struct acpi_table_fadt);

	/*
	 * Expand the 32-bit DSDT addresses to 64-bit as necessary.
	 * Later ACPICA code will always use the X 64-bit field.
	 */
	acpi_gbl_FADT.Xdsdt = acpi_tb_select_address("DSDT",
						     acpi_gbl_FADT.dsdt,
						     acpi_gbl_FADT.Xdsdt);
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_create_local_fadt
 *
 * PARAMETERS:  table               - Pointer to BIOS FADT
 *              length              - Length of the table
 *
 * RETURN:      None
 *
 * DESCRIPTION: Get a local copy of the FADT and convert it to a common format.
 *              Performs validation on some important FADT fields.
 *
 * NOTE:        We create a local copy of the FADT regardless of the version.
 *
 ******************************************************************************/
static void __init acpi_tb_create_local_fadt(struct acpi_table_header *table, u32 length)
{
	/*
	 * Check if the FADT is larger than the largest table that we expect
	 * (typically the current ACPI specification version). If so, truncate
	 * the table, and issue a warning.
	 */
	if (length > sizeof(struct acpi_table_fadt)) {
		pr_warn("FADT (revision %u) is longer than %s length, "
			"truncating length %u to %u",
			table->revision, ACPI_FADT_CONFORMANCE, length,
			(u32)sizeof(struct acpi_table_fadt));
	}

	/* Clear the entire local FADT */
	memset(&acpi_gbl_FADT, 0, sizeof(struct acpi_table_fadt));

	/* Copy the original FADT, up to sizeof (struct acpi_table_fadt) */
	memcpy(&acpi_gbl_FADT, table, min((size_t)length, sizeof(struct acpi_table_fadt)));

	/* Take a copy of the Hardware Reduced flag */
	if (acpi_gbl_FADT.flags & ACPI_FADT_HW_REDUCED)
		acpi_gbl_reduced_hardware = true;

	/* Convert the local copy of the FADT to the common internal format */
	acpi_tb_convert_fadt();
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_tb_parse_fadt
 *
 * PARAMETERS:  None
 *
 * RETURN:      None
 *
 * DESCRIPTION: Initialize the FADT, DSDT and FACS tables
 *              (FADT contains the addresses of the DSDT and FACS)
 *
 ******************************************************************************/
void __init acpi_tb_parse_fadt(void)
{
	u32 length;
	struct acpi_table_header *table;
	struct acpi_table_desc *fadt_desc;
	int status;

	/*
	 * The FADT has multiple versions with different lengths,
	 * and it contains pointers to both the DSDT and FACS tables.
	 *
	 * Get a local copy of the FADT and convert it to a common format
	 * Map entire FADT, assumed to be smaller than one page.
	 */
	fadt_desc = &acpi_tables[acpi_gbl_fadt_index];
	status = acpi_tb_get_table(fadt_desc, &table);
	if (status)
		return;
	length = fadt_desc->length;

	/* Create a local copy of the FADT in common ACPI 2.0+ format */
	acpi_tb_create_local_fadt(table, length);

	/* All done with the real FADT, unmap it */
	acpi_tb_put_table(fadt_desc);

	/*
	 * TODO:
	 * FADT has some pointers point to other ACPI tables
	 * But for now Lego does not need these info, so leave it.
	 */
}
