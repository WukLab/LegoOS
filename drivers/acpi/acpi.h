/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ACPI_H_
#define _ACPI_H_

/*
 * About EBDA:
 *
 * Some BIOSes store additional data in the last 1 KB of conventional memory.
 * In general this so-called Extended BIOS Data Area will be used to hold data
 * for a mouse port, hard disk parameters and disk track buffers. The EBDA
 * segment is normally stored in the BIOS Data Area at 0040:000Eh, a location
 * that was originally used to store the port number for parallel port 4. This
 * pointer is typically set to 9FC0h, representing a 1 KB memory area just below
 * the top of conventional memory. A few systems may reserve 2 KB or even 4 KB
 * for the EBDA.
 */

/* Constants used in searching for the RSDP in low memory */
#define ACPI_EBDA_PTR_LOCATION          0x0000040E
#define ACPI_EBDA_PTR_LENGTH            2
#define ACPI_EBDA_WINDOW_SIZE           1024

#define ACPI_HI_RSDP_WINDOW_BASE        0x000E0000
#define ACPI_HI_RSDP_WINDOW_SIZE        0x00020000
#define ACPI_RSDP_SCAN_STEP             16

#define AE_BAD_SIGNATURE                (0x0001)
#define AE_BAD_HEADER                   (0x0002)
#define AE_BAD_CHECKSUM                 (0x0003)
#define AE_BAD_VALUE                    (0x0004)
#define AE_INVALID_TABLE_LENGTH         (0x0005)

/* RSDP checksums */
#define ACPI_RSDP_CHECKSUM_LENGTH       20
#define ACPI_RSDP_XCHECKSUM_LENGTH      36

#define ACPI_CAST_PTR(t, p)             ((t *)(void *)(p))
#define ACPI_VALIDATE_RSDP_SIG(a)       (!strncmp((char *)(a), ACPI_SIG_RSDP, 8))

#define ACPI_COMPARE_NAME(a,b)          (*ACPI_CAST_PTR (u32, (a)) == *ACPI_CAST_PTR (u32, (b)))
#define ACPI_MOVE_NAME(dest,src)        (*ACPI_CAST_PTR (u32, (dest)) = *ACPI_CAST_PTR (u32, (src)))

/*
 * printf() format helper. This macros is a workaround for the difficulties
 * with emitting 64-bit integers and 64-bit pointers with the same code
 * for both 32-bit and 64-bit hosts.
 */
#define ACPI_LODWORD(integer64)         ((u32)  (u64)(integer64))
#define ACPI_HIDWORD(integer64)         ((u32)(((u64)(integer64)) >> 32))
#define ACPI_FORMAT_UINT64(i)           ACPI_HIDWORD(i), ACPI_LODWORD(i)

#endif /* _ACPI_H_ */
