/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_ACPI_H_
#define _LEGO_ACPI_H_

#include <lego/numa.h>
#include <lego/types.h>

/* Pointer manipulation */
#define acpi_uintptr_t                  void *
typedef u64 acpi_size;
typedef u64 acpi_io_address;
typedef u64 acpi_physical_address;

#define ACPI_CAST_INDIRECT_PTR(t, p)    ((t **) (acpi_uintptr_t) (p))
#define ACPI_ADD_PTR(t, a, b)           ACPI_CAST_PTR (t, (ACPI_CAST_PTR (u8, (a)) + (acpi_size)(b)))
#define ACPI_SUB_PTR(t, a, b)           ACPI_CAST_PTR (t, (ACPI_CAST_PTR (u8, (a)) - (acpi_size)(b)))
#define ACPI_PTR_DIFF(a, b)             (acpi_size) (ACPI_CAST_PTR (u8, (a)) - ACPI_CAST_PTR (u8, (b)))
#define ACPI_OFFSET(d, f)               ACPI_PTR_DIFF (&(((d *) 0)->f), (void *) NULL)

/* 16-bit source, 16/32/64 destination */
#define ACPI_MOVE_16_TO_16(d, s)        *(u16 *)(void *)(d) = *(u16 *)(void *)(s)
#define ACPI_MOVE_16_TO_32(d, s)        *(u32 *)(void *)(d) = *(u16 *)(void *)(s)
#define ACPI_MOVE_16_TO_64(d, s)        *(u64 *)(void *)(d) = *(u16 *)(void *)(s)

/* 32-bit source, 16/32/64 destination */
#define ACPI_MOVE_32_TO_16(d, s)        ACPI_MOVE_16_TO_16(d, s)	/* Truncate to 16 */
#define ACPI_MOVE_32_TO_32(d, s)        *(u32 *)(void *)(d) = *(u32 *)(void *)(s)
#define ACPI_MOVE_32_TO_64(d, s)        *(u64 *)(void *)(d) = *(u32 *)(void *)(s)

/* 64-bit source, 16/32/64 destination */
#define ACPI_MOVE_64_TO_16(d, s)        ACPI_MOVE_16_TO_16(d, s)	/* Truncate to 16 */
#define ACPI_MOVE_64_TO_32(d, s)        ACPI_MOVE_32_TO_32(d, s)	/* Truncate to 32 */
#define ACPI_MOVE_64_TO_64(d, s)        *(u64 *)(void *)(d) = *(u64 *)(void *)(s)

enum acpi_irq_model_id {
	ACPI_IRQ_MODEL_PIC = 0,
	ACPI_IRQ_MODEL_IOAPIC,
	ACPI_IRQ_MODEL_IOSAPIC,
	ACPI_IRQ_MODEL_PLATFORM,
	ACPI_IRQ_MODEL_GIC,
	ACPI_IRQ_MODEL_COUNT
};

/*
 * Values for description table header signatures for tables defined in this
 * file. Useful because they make it more difficult to inadvertently type in
 * the wrong signature.
 */
#define ACPI_SIG_RSDP	"RSD PTR "	/* Root System Description Pointer */
#define ACPI_SIG_DSDT	"DSDT"		/* Differentiated System Description Table */
#define ACPI_SIG_FADT	"FACP"		/* Fixed ACPI Description Table */
#define ACPI_SIG_FACS	"FACS"		/* Firmware ACPI Control Structure */
#define ACPI_SIG_OSDT	"OSDT"		/* Override System Description Table */
#define ACPI_SIG_PSDT	"PSDT"		/* Persistent System Description Table */
#define ACPI_SIG_RSDT	"RSDT"		/* Root System Description Table */
#define ACPI_SIG_XSDT	"XSDT"		/* Extended  System Description Table */
#define ACPI_SIG_SSDT	"SSDT"		/* Secondary System Description Table */
#define ACPI_RSDP_NAME	"RSDP"		/* Short name for RSDP, not signature */
#define ACPI_SIG_BERT	"BERT"		/* Boot Error Record Table */
#define ACPI_SIG_CPEP	"CPEP"		/* Corrected Platform Error Polling table */
#define ACPI_SIG_ECDT	"ECDT"		/* Embedded Controller Boot Resources Table */
#define ACPI_SIG_EINJ	"EINJ"		/* Error Injection table */
#define ACPI_SIG_ERST	"ERST"		/* Error Record Serialization Table */
#define ACPI_SIG_HEST	"HEST"		/* Hardware Error Source Table */
#define ACPI_SIG_MADT	"APIC"		/* Multiple APIC Description Table */
#define ACPI_SIG_MSCT	"MSCT"		/* Maximum System Characteristics Table */
#define ACPI_SIG_SBST	"SBST"		/* Smart Battery Specification Table */
#define ACPI_SIG_SLIT	"SLIT"		/* System Locality Distance Information Table */
#define ACPI_SIG_SRAT	"SRAT"		/* System Resource Affinity Table */
#define ACPI_SIG_NFIT	"NFIT"		/* NVDIMM Firmware Interface Table */
#define ACPI_SIG_HPET	"HPET"		/* High Precision Event Timer table */
#define ACPI_SIG_BOOT	"BOOT"		/* Simple Boot Flag Table */

#define ACPI_SIG_MCFG           "MCFG"	/* PCI Memory Mapped Configuration table */

/*
 * All tables and structures must be byte-packed to match the ACPI
 * specification, since the tables are provided by the system BIOS
 */
#pragma pack(1)

#define ACPI_NAME_SIZE		4
#define ACPI_OEM_ID_SIZE	6
#define ACPI_OEM_TABLE_ID_SIZE	8

/*******************************************************************************
 *
 * Master ACPI Table Header. This common header is used by all ACPI tables
 * except the RSDP and FACS.
 *
 ******************************************************************************/
struct acpi_table_header {
	char signature[ACPI_NAME_SIZE];			/* ASCII table signature */
	u32 length;					/* Length of table in bytes, including this header */
	u8 revision;					/* ACPI Specification minor version number */
	u8 checksum;					/* To make sum of entire table == 0 */
	char oem_id[ACPI_OEM_ID_SIZE];			/* ASCII OEM identification */
	char oem_table_id[ACPI_OEM_TABLE_ID_SIZE];	/* ASCII OEM table identification */
	u32 oem_revision;				/* OEM revision number */
	char asl_compiler_id[ACPI_NAME_SIZE];		/* ASCII ASL compiler vendor ID */
	u32 asl_compiler_revision;			/* ASL compiler version */
};

/*******************************************************************************
 *
 * RSDP - Root System Description Pointer (Signature is "RSD PTR ")
 *        Version 2
 *
 ******************************************************************************/
struct acpi_table_rsdp {
	char signature[8];			/* ACPI signature, contains "RSD PTR " */
	u8 checksum;				/* ACPI 1.0 checksum */
	char oem_id[ACPI_OEM_ID_SIZE];		/* OEM identification */
	u8 revision;				/* Must be (0) for ACPI 1.0 or (2) for ACPI 2.0+ */
	u32 rsdt_physical_address;		/* 32-bit physical address of the RSDT */
	u32 length;				/* Table length in bytes, including header (ACPI 2.0+) */
	u64 xsdt_physical_address;		/* 64-bit physical address of the XSDT (ACPI 2.0+) */
	u8 extended_checksum;			/* Checksum of entire table (ACPI 2.0+) */
	u8 reserved[3];				/* Reserved, must be zero */
};

/*******************************************************************************
 *
 * RSDT/XSDT - Root System Description Tables
 *             Version 1 (both)
 *
 ******************************************************************************/
struct acpi_table_rsdt {
	struct acpi_table_header header;	/* Common ACPI table header */
	u32 table_offset_entry[1];		/* Array of pointers to ACPI tables */
};

struct acpi_table_xsdt {
	struct acpi_table_header header;	/* Common ACPI table header */
	u64 table_offset_entry[1];		/* Array of pointers to ACPI tables */
};

#define ACPI_RSDT_ENTRY_SIZE        (sizeof (u32))
#define ACPI_XSDT_ENTRY_SIZE        (sizeof (u64))

/*******************************************************************************
 *
 * GAS - Generic Address Structure (ACPI 2.0+)
 *
 * Note: Since this structure is used in the ACPI tables, it is byte aligned.
 * If misaligned access is not supported by the hardware, accesses to the
 * 64-bit Address field must be performed with care.
 *
 ******************************************************************************/
struct acpi_generic_address {
	u8 space_id;		/* Address space where struct or register exists */
	u8 bit_width;		/* Size in bits of given register */
	u8 bit_offset;		/* Bit offset within the register */
	u8 access_width;	/* Minimum Access size (ACPI 3.0) */
	u64 address;		/* 64-bit address of struct or register */
};

/*******************************************************************************
 *
 * FACS - Firmware ACPI Control Structure (FACS)
 *
 ******************************************************************************/
struct acpi_table_facs {
	char signature[4];	/* ASCII table signature */
	u32 length;		/* Length of structure, in bytes */
	u32 hardware_signature;	/* Hardware configuration signature */
	u32 firmware_waking_vector;	/* 32-bit physical address of the Firmware Waking Vector */
	u32 global_lock;	/* Global Lock for shared hardware resources */
	u32 flags;
	u64 xfirmware_waking_vector;	/* 64-bit version of the Firmware Waking Vector (ACPI 2.0+) */
	u8 version;		/* Version of this table (ACPI 2.0+) */
	u8 reserved[3];		/* Reserved, must be zero */
	u32 ospm_flags;		/* Flags to be set by OSPM (ACPI 4.0) */
	u8 reserved1[24];	/* Reserved, must be zero */
};

/* Masks for global_lock flag field above */
#define ACPI_GLOCK_PENDING          (1)		/* 00: Pending global lock ownership */
#define ACPI_GLOCK_OWNED            (1<<1)	/* 01: Global lock is owned */

/* Masks for Flags field above  */
#define ACPI_FACS_S4_BIOS_PRESENT   (1)		/* 00: S4BIOS support is present */
#define ACPI_FACS_64BIT_WAKE        (1<<1)	/* 01: 64-bit wake vector supported (ACPI 4.0) */

/* Masks for ospm_flags field above */
#define ACPI_FACS_64BIT_ENVIRONMENT (1)	/* 00: 64-bit wake environment is required (ACPI 4.0) */

/*******************************************************************************
 *
 * FADT - Fixed ACPI Description Table (Signature "FACP")
 *        Version 6
 *
 ******************************************************************************/
/* Fields common to all versions of the FADT */
struct acpi_table_fadt {
	struct acpi_table_header header;	/* Common ACPI table header */
	u32 facs;		/* 32-bit physical address of FACS */
	u32 dsdt;		/* 32-bit physical address of DSDT */
	u8 model;		/* System Interrupt Model (ACPI 1.0) - not used in ACPI 2.0+ */
	u8 preferred_profile;	/* Conveys preferred power management profile to OSPM. */
	u16 sci_interrupt;	/* System vector of SCI interrupt */
	u32 smi_command;	/* 32-bit Port address of SMI command port */
	u8 acpi_enable;		/* Value to write to SMI_CMD to enable ACPI */
	u8 acpi_disable;	/* Value to write to SMI_CMD to disable ACPI */
	u8 s4_bios_request;	/* Value to write to SMI_CMD to enter S4BIOS state */
	u8 pstate_control;	/* Processor performance state control */
	u32 pm1a_event_block;	/* 32-bit port address of Power Mgt 1a Event Reg Blk */
	u32 pm1b_event_block;	/* 32-bit port address of Power Mgt 1b Event Reg Blk */
	u32 pm1a_control_block;	/* 32-bit port address of Power Mgt 1a Control Reg Blk */
	u32 pm1b_control_block;	/* 32-bit port address of Power Mgt 1b Control Reg Blk */
	u32 pm2_control_block;	/* 32-bit port address of Power Mgt 2 Control Reg Blk */
	u32 pm_timer_block;	/* 32-bit port address of Power Mgt Timer Ctrl Reg Blk */
	u32 gpe0_block;		/* 32-bit port address of General Purpose Event 0 Reg Blk */
	u32 gpe1_block;		/* 32-bit port address of General Purpose Event 1 Reg Blk */
	u8 pm1_event_length;	/* Byte Length of ports at pm1x_event_block */
	u8 pm1_control_length;	/* Byte Length of ports at pm1x_control_block */
	u8 pm2_control_length;	/* Byte Length of ports at pm2_control_block */
	u8 pm_timer_length;	/* Byte Length of ports at pm_timer_block */
	u8 gpe0_block_length;	/* Byte Length of ports at gpe0_block */
	u8 gpe1_block_length;	/* Byte Length of ports at gpe1_block */
	u8 gpe1_base;		/* Offset in GPE number space where GPE1 events start */
	u8 cst_control;		/* Support for the _CST object and C-States change notification */
	u16 c2_latency;		/* Worst case HW latency to enter/exit C2 state */
	u16 c3_latency;		/* Worst case HW latency to enter/exit C3 state */
	u16 flush_size;		/* Processor memory cache line width, in bytes */
	u16 flush_stride;	/* Number of flush strides that need to be read */
	u8 duty_offset;		/* Processor duty cycle index in processor P_CNT reg */
	u8 duty_width;		/* Processor duty cycle value bit width in P_CNT register */
	u8 day_alarm;		/* Index to day-of-month alarm in RTC CMOS RAM */
	u8 month_alarm;		/* Index to month-of-year alarm in RTC CMOS RAM */
	u8 century;		/* Index to century in RTC CMOS RAM */
	u16 boot_flags;		/* IA-PC Boot Architecture Flags (see below for individual flags) */
	u8 reserved;		/* Reserved, must be zero */
	u32 flags;		/* Miscellaneous flag bits (see below for individual flags) */
	struct acpi_generic_address reset_register;	/* 64-bit address of the Reset register */
	u8 reset_value;		/* Value to write to the reset_register port to reset the system */
	u16 arm_boot_flags;	/* ARM-Specific Boot Flags (see below for individual flags) (ACPI 5.1) */
	u8 minor_revision;	/* FADT Minor Revision (ACPI 5.1) */
	u64 Xfacs;		/* 64-bit physical address of FACS */
	u64 Xdsdt;		/* 64-bit physical address of DSDT */
	struct acpi_generic_address xpm1a_event_block;	/* 64-bit Extended Power Mgt 1a Event Reg Blk address */
	struct acpi_generic_address xpm1b_event_block;	/* 64-bit Extended Power Mgt 1b Event Reg Blk address */
	struct acpi_generic_address xpm1a_control_block;	/* 64-bit Extended Power Mgt 1a Control Reg Blk address */
	struct acpi_generic_address xpm1b_control_block;	/* 64-bit Extended Power Mgt 1b Control Reg Blk address */
	struct acpi_generic_address xpm2_control_block;	/* 64-bit Extended Power Mgt 2 Control Reg Blk address */
	struct acpi_generic_address xpm_timer_block;	/* 64-bit Extended Power Mgt Timer Ctrl Reg Blk address */
	struct acpi_generic_address xgpe0_block;	/* 64-bit Extended General Purpose Event 0 Reg Blk address */
	struct acpi_generic_address xgpe1_block;	/* 64-bit Extended General Purpose Event 1 Reg Blk address */
	struct acpi_generic_address sleep_control;	/* 64-bit Sleep Control register (ACPI 5.0) */
	struct acpi_generic_address sleep_status;	/* 64-bit Sleep Status register (ACPI 5.0) */
	u64 hypervisor_id;	/* Hypervisor Vendor ID (ACPI 6.0) */
};

/* Masks for FADT IA-PC Boot Architecture Flags (boot_flags) [Vx]=Introduced in this FADT revision */

#define ACPI_FADT_LEGACY_DEVICES    (1)  	/* 00: [V2] System has LPC or ISA bus devices */
#define ACPI_FADT_8042              (1<<1)	/* 01: [V3] System has an 8042 controller on port 60/64 */
#define ACPI_FADT_NO_VGA            (1<<2)	/* 02: [V4] It is not safe to probe for VGA hardware */
#define ACPI_FADT_NO_MSI            (1<<3)	/* 03: [V4] Message Signaled Interrupts (MSI) must not be enabled */
#define ACPI_FADT_NO_ASPM           (1<<4)	/* 04: [V4] PCIe ASPM control must not be enabled */
#define ACPI_FADT_NO_CMOS_RTC       (1<<5)	/* 05: [V5] No CMOS real-time clock present */

#define FADT2_REVISION_ID               3

/* Masks for FADT ARM Boot Architecture Flags (arm_boot_flags) ACPI 5.1 */

#define ACPI_FADT_PSCI_COMPLIANT    (1)	/* 00: [V5+] PSCI 0.2+ is implemented */
#define ACPI_FADT_PSCI_USE_HVC      (1<<1)	/* 01: [V5+] HVC must be used instead of SMC as the PSCI conduit */

/* Masks for FADT flags */

#define ACPI_FADT_WBINVD            (1)	/* 00: [V1] The WBINVD instruction works properly */
#define ACPI_FADT_WBINVD_FLUSH      (1<<1)	/* 01: [V1] WBINVD flushes but does not invalidate caches */
#define ACPI_FADT_C1_SUPPORTED      (1<<2)	/* 02: [V1] All processors support C1 state */
#define ACPI_FADT_C2_MP_SUPPORTED   (1<<3)	/* 03: [V1] C2 state works on MP system */
#define ACPI_FADT_POWER_BUTTON      (1<<4)	/* 04: [V1] Power button is handled as a control method device */
#define ACPI_FADT_SLEEP_BUTTON      (1<<5)	/* 05: [V1] Sleep button is handled as a control method device */
#define ACPI_FADT_FIXED_RTC         (1<<6)	/* 06: [V1] RTC wakeup status is not in fixed register space */
#define ACPI_FADT_S4_RTC_WAKE       (1<<7)	/* 07: [V1] RTC alarm can wake system from S4 */
#define ACPI_FADT_32BIT_TIMER       (1<<8)	/* 08: [V1] ACPI timer width is 32-bit (0=24-bit) */
#define ACPI_FADT_DOCKING_SUPPORTED (1<<9)	/* 09: [V1] Docking supported */
#define ACPI_FADT_RESET_REGISTER    (1<<10)	/* 10: [V2] System reset via the FADT RESET_REG supported */
#define ACPI_FADT_SEALED_CASE       (1<<11)	/* 11: [V3] No internal expansion capabilities and case is sealed */
#define ACPI_FADT_HEADLESS          (1<<12)	/* 12: [V3] No local video capabilities or local input devices */
#define ACPI_FADT_SLEEP_TYPE        (1<<13)	/* 13: [V3] Must execute native instruction after writing  SLP_TYPx register */
#define ACPI_FADT_PCI_EXPRESS_WAKE  (1<<14)	/* 14: [V4] System supports PCIEXP_WAKE (STS/EN) bits (ACPI 3.0) */
#define ACPI_FADT_PLATFORM_CLOCK    (1<<15)	/* 15: [V4] OSPM should use platform-provided timer (ACPI 3.0) */
#define ACPI_FADT_S4_RTC_VALID      (1<<16)	/* 16: [V4] Contents of RTC_STS valid after S4 wake (ACPI 3.0) */
#define ACPI_FADT_REMOTE_POWER_ON   (1<<17)	/* 17: [V4] System is compatible with remote power on (ACPI 3.0) */
#define ACPI_FADT_APIC_CLUSTER      (1<<18)	/* 18: [V4] All local APICs must use cluster model (ACPI 3.0) */
#define ACPI_FADT_APIC_PHYSICAL     (1<<19)	/* 19: [V4] All local xAPICs must use physical dest mode (ACPI 3.0) */
#define ACPI_FADT_HW_REDUCED        (1<<20)	/* 20: [V5] ACPI hardware is not implemented (ACPI 5.0) */
#define ACPI_FADT_LOW_POWER_S0      (1<<21)	/* 21: [V5] S0 power savings are equal or better than S3 (ACPI 5.0) */

/* Macros used to generate offsets to specific table fields */
#define ACPI_FADT_OFFSET(f)	(u16) ACPI_OFFSET (struct acpi_table_fadt, f)

/*
 * Sizes of the various flavors of FADT. We need to look closely
 * at the FADT length because the version number essentially tells
 * us nothing because of many BIOS bugs where the version does not
 * match the expected length. In other words, the length of the
 * FADT is the bottom line as to what the version really is.
 *
 * For reference, the values below are as follows:
 *     FADT V1 size: 0x074
 *     FADT V2 size: 0x084
 *     FADT V3 size: 0x0F4
 *     FADT V4 size: 0x0F4
 *     FADT V5 size: 0x10C
 *     FADT V6 size: 0x114
 */
#define ACPI_FADT_V1_SIZE       (u32) (ACPI_FADT_OFFSET (flags) + 4)
#define ACPI_FADT_V2_SIZE       (u32) (ACPI_FADT_OFFSET (minor_revision) + 1)
#define ACPI_FADT_V3_SIZE       (u32) (ACPI_FADT_OFFSET (sleep_control))
#define ACPI_FADT_V5_SIZE       (u32) (ACPI_FADT_OFFSET (hypervisor_id))
#define ACPI_FADT_V6_SIZE       (u32) (sizeof (struct acpi_table_fadt))

#define ACPI_FADT_CONFORMANCE   "ACPI 6.1 (FADT version 6)"

/*******************************************************************************
 *
 * BOOT - Simple Boot Flag Table
 *        Version 1
 *
 * Conforms to the "Simple Boot Flag Specification", Version 2.1
 *
 ******************************************************************************/
struct acpi_table_boot {
	struct acpi_table_header header;	/* Common ACPI table header */
	u8 cmos_index;		/* Index in CMOS RAM for the boot register */
	u8 reserved[3];
};

/*******************************************************************************
 *
 * HPET - High Precision Event Timer table
 *        Version 1
 *
 * Conforms to "IA-PC HPET (High Precision Event Timers) Specification",
 * Version 1.0a, October 2004
 *
 ******************************************************************************/
struct acpi_table_hpet {
	struct acpi_table_header header;	/* Common ACPI table header */
	u32 id;					/* Hardware ID of event timer block */
	struct acpi_generic_address address;	/* Address of event timer block */
	u8 sequence;				/* HPET sequence number */
	u16 minimum_tick;			/* Main counter min tick, periodic mode */
	u8 flags;
};

/**
 * MADT
 * Multiple APIC Description Table
 * Version 3
 */

/* Generic subtable header (used in MADT, SRAT, etc.) */
struct acpi_subtable_header {
	u8 type;
	u8 length;
};

/* Table Handlers */

typedef int (*acpi_tbl_table_handler)(struct acpi_table_header *table);

typedef int (*acpi_tbl_entry_handler)(struct acpi_subtable_header *header,
				      const unsigned long end);

/*******************************************************************************
 *
 * MADT - Multiple APIC Description Table
 *        Version 3
 *
 ******************************************************************************/
struct acpi_table_madt {
	struct acpi_table_header header;	/* Common ACPI table header */
	u32 address;				/* Physical address of local APIC */
	u32 flags;
};

/* Values for MADT subtable type in struct acpi_subtable_header */
enum acpi_madt_type {
	ACPI_MADT_TYPE_LOCAL_APIC = 0,
	ACPI_MADT_TYPE_IO_APIC = 1,
	ACPI_MADT_TYPE_INTERRUPT_OVERRIDE = 2,
	ACPI_MADT_TYPE_NMI_SOURCE = 3,
	ACPI_MADT_TYPE_LOCAL_APIC_NMI = 4,
	ACPI_MADT_TYPE_LOCAL_APIC_OVERRIDE = 5,
	ACPI_MADT_TYPE_IO_SAPIC = 6,
	ACPI_MADT_TYPE_LOCAL_SAPIC = 7,
	ACPI_MADT_TYPE_INTERRUPT_SOURCE = 8,
	ACPI_MADT_TYPE_LOCAL_X2APIC = 9,
	ACPI_MADT_TYPE_LOCAL_X2APIC_NMI = 10,
	ACPI_MADT_TYPE_GENERIC_INTERRUPT = 11,
	ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR = 12,
	ACPI_MADT_TYPE_GENERIC_MSI_FRAME = 13,
	ACPI_MADT_TYPE_GENERIC_REDISTRIBUTOR = 14,
	ACPI_MADT_TYPE_GENERIC_TRANSLATOR = 15,
	ACPI_MADT_TYPE_RESERVED = 16	/* 16 and greater are reserved */
};

/*
 * MADT Subtables, correspond to Type in struct acpi_subtable_header
 */

/* 0: Processor Local APIC */

struct acpi_madt_local_apic {
	struct acpi_subtable_header header;
	u8 processor_id;	/* ACPI processor id */
	u8 id;			/* Processor's local APIC id */
	u32 lapic_flags;
};

/* 1: IO APIC */

struct acpi_madt_io_apic {
	struct acpi_subtable_header header;
	u8 id;			/* I/O APIC ID */
	u8 reserved;		/* reserved - must be zero */
	u32 address;		/* APIC physical address */
	u32 global_irq_base;	/* Global system interrupt where INTI lines start */
};

/* 2: Interrupt Override */

struct acpi_madt_interrupt_override {
	struct acpi_subtable_header header;
	u8 bus;			/* 0 - ISA */
	u8 source_irq;		/* Interrupt source (IRQ) */
	u32 global_irq;		/* Global system interrupt */
	u16 inti_flags;
};

/* 3: NMI Source */

struct acpi_madt_nmi_source {
	struct acpi_subtable_header header;
	u16 inti_flags;
	u32 global_irq;		/* Global system interrupt */
};

/* 4: Local APIC NMI */

struct acpi_madt_local_apic_nmi {
	struct acpi_subtable_header header;
	u8 processor_id;	/* ACPI processor id */
	u16 inti_flags;
	u8 lint;		/* LINTn to which NMI is connected */
};

/* 5: Address Override */

struct acpi_madt_local_apic_override {
	struct acpi_subtable_header header;
	u16 reserved;		/* Reserved, must be zero */
	u64 address;		/* APIC physical address */
};

/* 6: I/O Sapic */

struct acpi_madt_io_sapic {
	struct acpi_subtable_header header;
	u8 id;			/* I/O SAPIC ID */
	u8 reserved;		/* Reserved, must be zero */
	u32 global_irq_base;	/* Global interrupt for SAPIC start */
	u64 address;		/* SAPIC physical address */
};

/* 7: Local Sapic */

struct acpi_madt_local_sapic {
	struct acpi_subtable_header header;
	u8 processor_id;	/* ACPI processor id */
	u8 id;			/* SAPIC ID */
	u8 eid;			/* SAPIC EID */
	u8 reserved[3];		/* Reserved, must be zero */
	u32 lapic_flags;
	u32 uid;		/* Numeric UID - ACPI 3.0 */
	char uid_string[1];	/* String UID  - ACPI 3.0 */
};

/* 8: Platform Interrupt Source */

struct acpi_madt_interrupt_source {
	struct acpi_subtable_header header;
	u16 inti_flags;
	u8 type;		/* 1=PMI, 2=INIT, 3=corrected */
	u8 id;			/* Processor ID */
	u8 eid;			/* Processor EID */
	u8 io_sapic_vector;	/* Vector value for PMI interrupts */
	u32 global_irq;		/* Global system interrupt */
	u32 flags;		/* Interrupt Source Flags */
};

/* Masks for Flags field above */

#define ACPI_MADT_CPEI_OVERRIDE     (1)

/* 9: Processor Local X2APIC (ACPI 4.0) */

struct acpi_madt_local_x2apic {
	struct acpi_subtable_header header;
	u16 reserved;		/* reserved - must be zero */
	u32 local_apic_id;	/* Processor x2APIC ID  */
	u32 lapic_flags;
	u32 uid;		/* ACPI processor UID */
};

/* 10: Local X2APIC NMI (ACPI 4.0) */

struct acpi_madt_local_x2apic_nmi {
	struct acpi_subtable_header header;
	u16 inti_flags;
	u32 uid;		/* ACPI processor UID */
	u8 lint;		/* LINTn to which NMI is connected */
	u8 reserved[3];		/* reserved - must be zero */
};

/* 11: Generic Interrupt (ACPI 5.0 + ACPI 6.0 changes) */

struct acpi_madt_generic_interrupt {
	struct acpi_subtable_header header;
	u16 reserved;		/* reserved - must be zero */
	u32 cpu_interface_number;
	u32 uid;
	u32 flags;
	u32 parking_version;
	u32 performance_interrupt;
	u64 parked_address;
	u64 base_address;
	u64 gicv_base_address;
	u64 gich_base_address;
	u32 vgic_interrupt;
	u64 gicr_base_address;
	u64 arm_mpidr;
	u8 efficiency_class;
	u8 reserved2[3];
};

/* Masks for Flags field above */

/* ACPI_MADT_ENABLED                    (1)      Processor is usable if set */
#define ACPI_MADT_PERFORMANCE_IRQ_MODE  (1<<1)	/* 01: Performance Interrupt Mode */
#define ACPI_MADT_VGIC_IRQ_MODE         (1<<2)	/* 02: VGIC Maintenance Interrupt mode */

/* 12: Generic Distributor (ACPI 5.0 + ACPI 6.0 changes) */

struct acpi_madt_generic_distributor {
	struct acpi_subtable_header header;
	u16 reserved;		/* reserved - must be zero */
	u32 gic_id;
	u64 base_address;
	u32 global_irq_base;
	u8 version;
	u8 reserved2[3];	/* reserved - must be zero */
};

/* Values for Version field above */

enum acpi_madt_gic_version {
	ACPI_MADT_GIC_VERSION_NONE = 0,
	ACPI_MADT_GIC_VERSION_V1 = 1,
	ACPI_MADT_GIC_VERSION_V2 = 2,
	ACPI_MADT_GIC_VERSION_V3 = 3,
	ACPI_MADT_GIC_VERSION_V4 = 4,
	ACPI_MADT_GIC_VERSION_RESERVED = 5	/* 5 and greater are reserved */
};

/* 13: Generic MSI Frame (ACPI 5.1) */

struct acpi_madt_generic_msi_frame {
	struct acpi_subtable_header header;
	u16 reserved;		/* reserved - must be zero */
	u32 msi_frame_id;
	u64 base_address;
	u32 flags;
	u16 spi_count;
	u16 spi_base;
};

/* Masks for Flags field above */

#define ACPI_MADT_OVERRIDE_SPI_VALUES   (1)

/* 14: Generic Redistributor (ACPI 5.1) */

struct acpi_madt_generic_redistributor {
	struct acpi_subtable_header header;
	u16 reserved;		/* reserved - must be zero */
	u64 base_address;
	u32 length;
};

/* 15: Generic Translator (ACPI 6.0) */

struct acpi_madt_generic_translator {
	struct acpi_subtable_header header;
	u16 reserved;		/* reserved - must be zero */
	u32 translation_id;
	u64 base_address;
	u32 reserved2;
};

/*
 * Common flags fields for MADT subtables
 */

/* MADT Local APIC flags */

#define ACPI_MADT_ENABLED           (1)	/* 00: Processor is usable if set */

/* MADT MPS INTI flags (inti_flags) */

#define ACPI_MADT_POLARITY_MASK     (3)	/* 00-01: Polarity of APIC I/O input signals */
#define ACPI_MADT_TRIGGER_MASK      (3<<2)	/* 02-03: Trigger mode of APIC input signals */

/* Values for MPS INTI flags */

#define ACPI_MADT_POLARITY_CONFORMS       0
#define ACPI_MADT_POLARITY_ACTIVE_HIGH    1
#define ACPI_MADT_POLARITY_RESERVED       2
#define ACPI_MADT_POLARITY_ACTIVE_LOW     3

#define ACPI_MADT_TRIGGER_CONFORMS        (0)
#define ACPI_MADT_TRIGGER_EDGE            (1<<2)
#define ACPI_MADT_TRIGGER_RESERVED        (2<<2)
#define ACPI_MADT_TRIGGER_LEVEL           (3<<2)

/*******************************************************************************
 *
 * SLIT - System Locality Distance Information Table
 *        Version 1
 *
 ******************************************************************************/
struct acpi_table_slit {
	struct acpi_table_header header;	/* Common ACPI table header */
	u64 locality_count;
	u8 entry[1];				/* Real size = localities^2 */
};

/*******************************************************************************
 *
 * SRAT - System Resource Affinity Table
 *        Version 3
 *
 ******************************************************************************/
struct acpi_table_srat {
	struct acpi_table_header header;	/* Common ACPI table header */
	u32 table_revision;			/* Must be value '1' */
	u64 reserved;				/* Reserved, must be zero */
};

/* Values for subtable type in struct acpi_subtable_header */
enum acpi_srat_type {
	ACPI_SRAT_TYPE_CPU_AFFINITY = 0,
	ACPI_SRAT_TYPE_MEMORY_AFFINITY = 1,
	ACPI_SRAT_TYPE_X2APIC_CPU_AFFINITY = 2,
	ACPI_SRAT_TYPE_GICC_AFFINITY = 3,
	ACPI_SRAT_TYPE_RESERVED = 4		/* 4 and greater are reserved */
};

/*
 * SRAT Subtables, correspond to Type in struct acpi_subtable_header
 */

/* 0: Processor Local APIC/SAPIC Affinity */
struct acpi_srat_cpu_affinity {
	struct acpi_subtable_header header;
	u8 proximity_domain_lo;
	u8 apic_id;
	u32 flags;
	u8 local_sapic_eid;
	u8 proximity_domain_hi[3];
	u32 clock_domain;
};

/* Flags */
#define ACPI_SRAT_CPU_USE_AFFINITY  (1)		/* 00: Use affinity structure */

/* 1: Memory Affinity */
struct acpi_srat_mem_affinity {
	struct acpi_subtable_header header;
	u32 proximity_domain;
	u16 reserved;
	u64 base_address;
	u64 length;
	u32 reserved1;
	u32 flags;
	u64 reserved2;
};

/* Flags */
#define ACPI_SRAT_MEM_ENABLED       (1)		/* 00: Use affinity structure */
#define ACPI_SRAT_MEM_HOT_PLUGGABLE (1<<1)	/* 01: Memory region is hot pluggable */
#define ACPI_SRAT_MEM_NON_VOLATILE  (1<<2)	/* 02: Memory region is non-volatile */

/* 2: Processor Local X2_APIC Affinity (ACPI 4.0) */
struct acpi_srat_x2apic_cpu_affinity {
	struct acpi_subtable_header header;
	u16 reserved;
	u32 proximity_domain;
	u32 apic_id;
	u32 flags;
	u32 clock_domain;
	u32 reserved2;
};

/* Flags for struct acpi_srat_cpu_affinity and struct acpi_srat_x2apic_cpu_affinity */
#define ACPI_SRAT_CPU_ENABLED       (1)		/* 00: Use affinity structure */

/* 3: GICC Affinity (ACPI 5.1) */
struct acpi_srat_gicc_affinity {
	struct acpi_subtable_header header;
	u32 proximity_domain;
	u32 acpi_processor_uid;
	u32 flags;
	u32 clock_domain;
};

/* Flags for struct acpi_srat_gicc_affinity */
#define ACPI_SRAT_GICC_ENABLED     (1)		/* 00: Use affinity structure */

/* Reset to default packing */
#pragma pack()

/*
 * LegoOS Internal Representations
 */

/* Internal table-related structures */
union acpi_name_union {
	u32 integer;
	char ascii[4];
};

/* Internal ACPI Table Descriptor. One per ACPI table. */
struct acpi_table_desc {
	u64 address;
	struct acpi_table_header *pointer;
	u32 length;		/* Length fixed at 32 bits (fixed in table header) */
	union acpi_name_union signature;
	u8 flags;
	u16 validation_count;
};

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

#define ACPI_COMPARE_NAME(a,b)          (*ACPI_CAST_PTR (u32, (a)) == *ACPI_CAST_PTR (u32, (b)))
#define ACPI_MOVE_NAME(dest,src)        (*ACPI_CAST_PTR (u32, (dest)) = *ACPI_CAST_PTR (u32, (src)))

/* Support for the special RSDP signature (8 characters) */
#define ACPI_VALIDATE_RSDP_SIG(a)       (!strncmp (ACPI_CAST_PTR (char, (a)), ACPI_SIG_RSDP, 8))
#define ACPI_MAKE_RSDP_SIG(dest)        (memcpy (ACPI_CAST_PTR (char, (dest)), ACPI_SIG_RSDP, 8))

/*
 * printf() format helper. This macros is a workaround for the difficulties
 * with emitting 64-bit integers and 64-bit pointers with the same code
 * for both 32-bit and 64-bit hosts.
 */
#define ACPI_LODWORD(integer64)         ((u32)  (u64)(integer64))
#define ACPI_HIDWORD(integer64)         ((u32)(((u64)(integer64)) >> 32))
#define ACPI_FORMAT_UINT64(i)           ACPI_HIDWORD(i), ACPI_LODWORD(i)

/* Proximity bitmap length */
#if MAX_NUMNODES > 256
# define MAX_PXM_DOMAINS	MAX_NUMNODES
#else
/* Old pxm spec is defined 8 bit */
# define MAX_PXM_DOMAINS	(256)
#endif

struct acpi_subtable_proc {
	int id;
	acpi_tbl_entry_handler handler;
	int count;
};

int __init
acpi_table_parse_entries_array(char *id,
			 unsigned long table_size,
			 struct acpi_subtable_proc *proc, int proc_num,
			 unsigned int max_entries);

void __init acpi_table_print_madt_entry(struct acpi_subtable_header *header);
void __init acpi_table_print_srat_entry(struct acpi_subtable_header *header);

int __init acpi_table_parse_entries(char *id, unsigned long table_size, int entry_id,
			 acpi_tbl_entry_handler handler, unsigned int max_entries);

int __init acpi_table_parse_madt(enum acpi_madt_type id,
				 acpi_tbl_entry_handler handler,
				 unsigned int max_entries);

int __init acpi_table_parse_srat(enum acpi_srat_type id,
				 acpi_tbl_entry_handler handler,
				 unsigned int max_entries);

int pxm_to_node(int pxm);
int node_to_pxm(int node);
int acpi_map_pxm_to_node(int pxm);

int __init acpi_parse_table(char *signature, acpi_tbl_table_handler handler);

/* Initializing all ACPI tables */
void __init acpi_table_init(void);

/* Arch-Specific boot-time table parsing */
void __init acpi_boot_parse_tables(void);

/* Arch-Specific boot-time NUMA setup */
void __init acpi_boot_numa_init(void);

#define BAD_MADT_ENTRY(entry, end) (					    \
		(!entry) || (unsigned long)entry + sizeof(*entry) > end ||  \
		((struct acpi_subtable_header *)entry)->length < sizeof(*entry))


/* Conform to ACPI 2.0 SLIT distance definitions */
#define LOCAL_DISTANCE		10
#define REMOTE_DISTANCE		20

int acpi_isa_irq_to_gsi(unsigned isa_irq, u32 *gsi);
extern int acpi_ioapic;

extern struct acpi_table_fadt acpi_gbl_FADT;

/*******************************************************************************
 *
 * MCFG - PCI Memory Mapped Configuration table and sub-table
 *        Version 1
 *
 * Conforms to "PCI Firmware Specification", Revision 3.0, June 20, 2005
 *
 ******************************************************************************/

struct acpi_table_mcfg {
	struct acpi_table_header header;	/* Common ACPI table header */
	u8 reserved[8];
};

/* Subtable */

struct acpi_mcfg_allocation {
	u64 address;		/* Base address, processor-relative */
	u16 pci_segment;	/* PCI segment group number */
	u8 start_bus_number;	/* Starting PCI Bus number */
	u8 end_bus_number;	/* Final PCI Bus number */
	u32 reserved;
};

#endif /* _LEGO_ACPI_H_ */
