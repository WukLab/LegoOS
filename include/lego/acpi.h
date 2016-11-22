/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_ACPI_H_
#define _LEGO_ACPI_H_

#include <lego/types.h>

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

#define ACPI_NAME_SIZE		4
#define ACPI_OEM_ID_SIZE	6
#define ACPI_OEM_TABLE_ID_SIZE	8

/**
 * Master ACPI Table Header
 * This common header is used by all ACPI tables except the RSDP and FACS.
 */
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

/**
 * RSDP
 * Root System Description Pointer (Signature is "RSD PTR ")
 * Version 2
 */
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

/**
 * RSDT/XSDT
 * Root System Description Tables
 * Version 1 (both)
 */
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
	u8 processor_id;			/* ACPI processor id */
	u8 id;					/* Processor's local APIC id */
	u32 lapic_flags;
};

/* 1: IO APIC */
struct acpi_madt_io_apic {
	struct acpi_subtable_header header;
	u8 id;					/* I/O APIC ID */
	u8 reserved;				/* reserved - must be zero */
	u32 address;				/* APIC physical address */
	u32 global_irq_base;			/* Global system interrupt where INTI lines start */
};

/* 2: Interrupt Override */
struct acpi_madt_interrupt_override {
	struct acpi_subtable_header header;
	u8 bus;					/* 0 - ISA */
	u8 source_irq;				/* Interrupt source (IRQ) */
	u32 global_irq;				/* Global system interrupt */
	u16 inti_flags;
};

/* 3: NMI Source */
struct acpi_madt_nmi_source {
	struct acpi_subtable_header header;
	u16 inti_flags;
	u32 global_irq;				/* Global system interrupt */
};

/* 4: Local APIC NMI */
struct acpi_madt_local_apic_nmi {
	struct acpi_subtable_header header;
	u8 processor_id;			/* ACPI processor id */
	u16 inti_flags;
	u8 lint;				/* LINTn to which NMI is connected */
};

/* 5: Address Override */
struct acpi_madt_local_apic_override {
	struct acpi_subtable_header header;
	u16 reserved;				/* Reserved, must be zero */
	u64 address;				/* APIC physical address */
};

/* 6: I/O Sapic */
struct acpi_madt_io_sapic {
	struct acpi_subtable_header header;
	u8 id;					/* I/O SAPIC ID */
	u8 reserved;				/* Reserved, must be zero */
	u32 global_irq_base;			/* Global interrupt for SAPIC start */
	u64 address;				/* SAPIC physical address */
};

/* 7: Local Sapic */
struct acpi_madt_local_sapic {
	struct acpi_subtable_header header;
	u8 processor_id;			/* ACPI processor id */
	u8 id;					/* SAPIC ID */
	u8 eid;					/* SAPIC EID */
	u8 reserved[3];				/* Reserved, must be zero */
	u32 lapic_flags;
	u32 uid;				/* Numeric UID - ACPI 3.0 */
	char uid_string[1];			/* String UID  - ACPI 3.0 */
};

/* 8: Platform Interrupt Source */
struct acpi_madt_interrupt_source {
	struct acpi_subtable_header header;
	u16 inti_flags;
	u8 type;				/* 1=PMI, 2=INIT, 3=corrected */
	u8 id;					/* Processor ID */
	u8 eid;					/* Processor EID */
	u8 io_sapic_vector;			/* Vector value for PMI interrupts */
	u32 global_irq;				/* Global system interrupt */
	u32 flags;				/* Interrupt Source Flags */
};

/* Masks for Flags field above */
#define ACPI_MADT_CPEI_OVERRIDE     (1)

/* 9: Processor Local X2APIC (ACPI 4.0) */
struct acpi_madt_local_x2apic {
	struct acpi_subtable_header header;
	u16 reserved;				/* reserved - must be zero */
	u32 local_apic_id;			/* Processor x2APIC ID  */
	u32 lapic_flags;
	u32 uid;				/* ACPI processor UID */
};

/* 10: Local X2APIC NMI (ACPI 4.0) */
struct acpi_madt_local_x2apic_nmi {
	struct acpi_subtable_header header;
	u16 inti_flags;
	u32 uid;				/* ACPI processor UID */
	u8 lint;				/* LINTn to which NMI is connected */
	u8 reserved[3];				/* reserved - must be zero */
};

/* 11: Generic Interrupt (ACPI 5.0 + ACPI 6.0 changes) */
struct acpi_madt_generic_interrupt {
	struct acpi_subtable_header header;
	u16 reserved;				/* reserved - must be zero */
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
	u16 reserved;				/* reserved - must be zero */
	u32 gic_id;
	u64 base_address;
	u32 global_irq_base;
	u8 version;
	u8 reserved2[3];			/* reserved - must be zero */
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
	u16 reserved;				/* reserved - must be zero */
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
	u16 reserved;				/* reserved - must be zero */
	u64 base_address;
	u32 length;
};

/* 15: Generic Translator (ACPI 6.0) */
struct acpi_madt_generic_translator {
	struct acpi_subtable_header header;
	u16 reserved;				/* reserved - must be zero */
	u32 translation_id;
	u64 base_address;
	u32 reserved2;
};

/*
 * Common flags fields for MADT subtables
 */

/* MADT Local APIC flags */
#define ACPI_MADT_ENABLED		(1)	/* 00: Processor is usable if set */

/* MADT MPS INTI flags (inti_flags) */
#define ACPI_MADT_POLARITY_MASK		(3)	/* 00-01: Polarity of APIC I/O input signals */
#define ACPI_MADT_TRIGGER_MASK		(3<<2)	/* 02-03: Trigger mode of APIC input signals */

/* Values for MPS INTI flags */
#define ACPI_MADT_POLARITY_CONFORMS       0
#define ACPI_MADT_POLARITY_ACTIVE_HIGH    1
#define ACPI_MADT_POLARITY_RESERVED       2
#define ACPI_MADT_POLARITY_ACTIVE_LOW     3

#define ACPI_MADT_TRIGGER_CONFORMS        (0)
#define ACPI_MADT_TRIGGER_EDGE            (1<<2)
#define ACPI_MADT_TRIGGER_RESERVED        (2<<2)
#define ACPI_MADT_TRIGGER_LEVEL           (3<<2)

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
	struct acpi_table_header *pointer;
	u64 address;
	/* Length fixed at 32 bits (fixed in table header) */
	u32 length;
	union acpi_name_union signature;
	u8 owner_id;
	u8 flags;
};

void __init acpi_table_init(void);

#endif /* _LEGO_ACPI_H_ */
