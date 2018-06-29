/*
 *	pci_regs.h
 *
 *	PCI standard defines
 *	Copyright 1994, Drew Eckhardt
 *	Copyright 1997--1999 Martin Mares <mj@ucw.cz>
 *
 *	For more information, please consult the following manuals (look at
 *	http://www.pcisig.com/ for how to get them):
 *
 *	PCI BIOS Specification
 *	PCI Local Bus Specification
 *	PCI to PCI Bridge Specification
 *	PCI System Design Guide
 *
 *	For HyperTransport information, please consult the following manuals
 *	from http://www.hypertransport.org
 *
 *	The HyperTransport I/O Link Specification
 */

#ifndef LEGO_PCI_REGS_H
#define LEGO_PCI_REGS_H

#include <lego/types.h>

/*
 * Under PCI, each device has 256 bytes of configuration address space,
 * of which the first 64 bytes are standardized as follows:
 */
#define PCI_STD_HEADER_SIZEOF	64
#define PCI_VENDOR_ID		0x00	/* 16 bits */
#define PCI_DEVICE_ID		0x02	/* 16 bits */
#define PCI_COMMAND		0x04	/* 16 bits */
#define  PCI_COMMAND_IO		0x1	/* Enable response in I/O space */
#define  PCI_COMMAND_MEMORY	0x2	/* Enable response in Memory space */
#define  PCI_COMMAND_MASTER	0x4	/* Enable bus mastering */
#define  PCI_COMMAND_SPECIAL	0x8	/* Enable response to special cycles */
#define  PCI_COMMAND_INVALIDATE	0x10	/* Use memory write and invalidate */
#define  PCI_COMMAND_VGA_PALETTE 0x20	/* Enable palette snooping */
#define  PCI_COMMAND_PARITY	0x40	/* Enable parity checking */
#define  PCI_COMMAND_WAIT 	0x80	/* Enable address/data stepping */
#define  PCI_COMMAND_SERR	0x100	/* Enable SERR */
#define  PCI_COMMAND_FAST_BACK	0x200	/* Enable back-to-back writes */
#define  PCI_COMMAND_INTX_DISABLE 0x400 /* INTx Emulation Disable */

#define PCI_STATUS		0x06	/* 16 bits */
#define  PCI_STATUS_INTERRUPT	0x08	/* Interrupt status */
#define  PCI_STATUS_CAP_LIST	0x10	/* Support Capability List */
#define  PCI_STATUS_66MHZ	0x20	/* Support 66 Mhz PCI 2.1 bus */
#define  PCI_STATUS_UDF		0x40	/* Support User Definable Features [obsolete] */
#define  PCI_STATUS_FAST_BACK	0x80	/* Accept fast-back to back */
#define  PCI_STATUS_PARITY	0x100	/* Detected parity error */
#define  PCI_STATUS_DEVSEL_MASK	0x600	/* DEVSEL timing */
#define  PCI_STATUS_DEVSEL_FAST		0x000
#define  PCI_STATUS_DEVSEL_MEDIUM	0x200
#define  PCI_STATUS_DEVSEL_SLOW		0x400
#define  PCI_STATUS_SIG_TARGET_ABORT	0x800 /* Set on target abort */
#define  PCI_STATUS_REC_TARGET_ABORT	0x1000 /* Master ack of " */
#define  PCI_STATUS_REC_MASTER_ABORT	0x2000 /* Set on master abort */
#define  PCI_STATUS_SIG_SYSTEM_ERROR	0x4000 /* Set when we drive SERR */
#define  PCI_STATUS_DETECTED_PARITY	0x8000 /* Set on parity error */

#define PCI_CLASS_REVISION	0x08	/* High 24 bits are class, low 8 revision */
#define PCI_REVISION_ID		0x08	/* Revision ID */
#define PCI_CLASS_PROG		0x09	/* Reg. Level Programming Interface */
#define PCI_CLASS_DEVICE	0x0a	/* Device class */

#define PCI_CACHE_LINE_SIZE	0x0c	/* 8 bits */
#define PCI_LATENCY_TIMER	0x0d	/* 8 bits */
#define PCI_HEADER_TYPE		0x0e	/* 8 bits */
#define  PCI_HEADER_TYPE_NORMAL		0
#define  PCI_HEADER_TYPE_BRIDGE		1
#define  PCI_HEADER_TYPE_CARDBUS	2

#define PCI_BIST		0x0f	/* 8 bits */
#define  PCI_BIST_CODE_MASK	0x0f	/* Return result */
#define  PCI_BIST_START		0x40	/* 1 to start BIST, 2 secs or less */
#define  PCI_BIST_CAPABLE	0x80	/* 1 if BIST capable */

/*
 * Base addresses specify locations in memory or I/O space.
 * Decoded size can be determined by writing a value of
 * 0xffffffff to the register, and reading it back.  Only
 * 1 bits are decoded.
 */
#define PCI_BASE_ADDRESS_0	0x10	/* 32 bits */
#define PCI_BASE_ADDRESS_1	0x14	/* 32 bits [htype 0,1 only] */
#define PCI_BASE_ADDRESS_2	0x18	/* 32 bits [htype 0 only] */
#define PCI_BASE_ADDRESS_3	0x1c	/* 32 bits */
#define PCI_BASE_ADDRESS_4	0x20	/* 32 bits */
#define PCI_BASE_ADDRESS_5	0x24	/* 32 bits */
#define  PCI_BASE_ADDRESS_SPACE		0x01	/* 0 = memory, 1 = I/O */
#define  PCI_BASE_ADDRESS_SPACE_IO	0x01
#define  PCI_BASE_ADDRESS_SPACE_MEMORY	0x00
#define  PCI_BASE_ADDRESS_MEM_TYPE_MASK	0x06
#define  PCI_BASE_ADDRESS_MEM_TYPE_32	0x00	/* 32 bit address */
#define  PCI_BASE_ADDRESS_MEM_TYPE_1M	0x02	/* Below 1M [obsolete] */
#define  PCI_BASE_ADDRESS_MEM_TYPE_64	0x04	/* 64 bit address */
#define  PCI_BASE_ADDRESS_MEM_PREFETCH	0x08	/* prefetchable? */
#define  PCI_BASE_ADDRESS_MEM_MASK	(~0x0fUL)
#define  PCI_BASE_ADDRESS_IO_MASK	(~0x03UL)
/* bit 1 is reserved if address_space = 1 */

/* Header type 0 (normal devices) */
#define PCI_CARDBUS_CIS		0x28
#define PCI_SUBSYSTEM_VENDOR_ID	0x2c
#define PCI_SUBSYSTEM_ID	0x2e
#define PCI_ROM_ADDRESS		0x30	/* Bits 31..11 are address, 10..1 reserved */
#define  PCI_ROM_ADDRESS_ENABLE	0x01
#define PCI_ROM_ADDRESS_MASK	(~0x7ffUL)

#define PCI_CAPABILITY_LIST	0x34	/* Offset of first capability list entry */

/* 0x35-0x3b are reserved */
#define PCI_INTERRUPT_LINE	0x3c	/* 8 bits */
#define PCI_INTERRUPT_PIN	0x3d	/* 8 bits */
#define PCI_MIN_GNT		0x3e	/* 8 bits */
#define PCI_MAX_LAT		0x3f	/* 8 bits */

/* Header type 1 (PCI-to-PCI bridges) */
#define PCI_PRIMARY_BUS		0x18	/* Primary bus number */
#define PCI_SECONDARY_BUS	0x19	/* Secondary bus number */
#define PCI_SUBORDINATE_BUS	0x1a	/* Highest bus number behind the bridge */
#define PCI_SEC_LATENCY_TIMER	0x1b	/* Latency timer for secondary interface */
#define PCI_IO_BASE		0x1c	/* I/O range behind the bridge */
#define PCI_IO_LIMIT		0x1d
#define  PCI_IO_RANGE_TYPE_MASK	0x0fUL	/* I/O bridging type */
#define  PCI_IO_RANGE_TYPE_16	0x00
#define  PCI_IO_RANGE_TYPE_32	0x01
#define  PCI_IO_RANGE_MASK	(~0x0fUL) /* Standard 4K I/O windows */
#define  PCI_IO_1K_RANGE_MASK	(~0x03UL) /* Intel 1K I/O windows */
#define PCI_SEC_STATUS		0x1e	/* Secondary status register, only bit 14 used */
#define PCI_MEMORY_BASE		0x20	/* Memory range behind */
#define PCI_MEMORY_LIMIT	0x22
#define  PCI_MEMORY_RANGE_TYPE_MASK 0x0fUL
#define  PCI_MEMORY_RANGE_MASK	(~0x0fUL)
#define PCI_PREF_MEMORY_BASE	0x24	/* Prefetchable memory range behind */
#define PCI_PREF_MEMORY_LIMIT	0x26
#define  PCI_PREF_RANGE_TYPE_MASK 0x0fUL
#define  PCI_PREF_RANGE_TYPE_32	0x00
#define  PCI_PREF_RANGE_TYPE_64	0x01
#define  PCI_PREF_RANGE_MASK	(~0x0fUL)
#define PCI_PREF_BASE_UPPER32	0x28	/* Upper half of prefetchable memory range */
#define PCI_PREF_LIMIT_UPPER32	0x2c
#define PCI_IO_BASE_UPPER16	0x30	/* Upper half of I/O addresses */
#define PCI_IO_LIMIT_UPPER16	0x32
/* 0x34 same as for htype 0 */
/* 0x35-0x3b is reserved */
#define PCI_ROM_ADDRESS1	0x38	/* Same as PCI_ROM_ADDRESS, but for htype 1 */
/* 0x3c-0x3d are same as for htype 0 */
#define PCI_BRIDGE_CONTROL	0x3e
#define  PCI_BRIDGE_CTL_PARITY	0x01	/* Enable parity detection on secondary interface */
#define  PCI_BRIDGE_CTL_SERR	0x02	/* The same for SERR forwarding */
#define  PCI_BRIDGE_CTL_ISA	0x04	/* Enable ISA mode */
#define  PCI_BRIDGE_CTL_VGA	0x08	/* Forward VGA addresses */
#define  PCI_BRIDGE_CTL_MASTER_ABORT	0x20  /* Report master aborts */
#define  PCI_BRIDGE_CTL_BUS_RESET	0x40	/* Secondary bus reset */
#define  PCI_BRIDGE_CTL_FAST_BACK	0x80	/* Fast Back2Back enabled on secondary interface */

/* Header type 2 (CardBus bridges) */
#define PCI_CB_CAPABILITY_LIST	0x14
/* 0x15 reserved */
#define PCI_CB_SEC_STATUS	0x16	/* Secondary status */
#define PCI_CB_PRIMARY_BUS	0x18	/* PCI bus number */
#define PCI_CB_CARD_BUS		0x19	/* CardBus bus number */
#define PCI_CB_SUBORDINATE_BUS	0x1a	/* Subordinate bus number */
#define PCI_CB_LATENCY_TIMER	0x1b	/* CardBus latency timer */
#define PCI_CB_MEMORY_BASE_0	0x1c
#define PCI_CB_MEMORY_LIMIT_0	0x20
#define PCI_CB_MEMORY_BASE_1	0x24
#define PCI_CB_MEMORY_LIMIT_1	0x28
#define PCI_CB_IO_BASE_0	0x2c
#define PCI_CB_IO_BASE_0_HI	0x2e
#define PCI_CB_IO_LIMIT_0	0x30
#define PCI_CB_IO_LIMIT_0_HI	0x32
#define PCI_CB_IO_BASE_1	0x34
#define PCI_CB_IO_BASE_1_HI	0x36
#define PCI_CB_IO_LIMIT_1	0x38
#define PCI_CB_IO_LIMIT_1_HI	0x3a
#define  PCI_CB_IO_RANGE_MASK	(~0x03UL)
/* 0x3c-0x3d are same as for htype 0 */
#define PCI_CB_BRIDGE_CONTROL	0x3e
#define  PCI_CB_BRIDGE_CTL_PARITY	0x01	/* Similar to standard bridge control register */
#define  PCI_CB_BRIDGE_CTL_SERR		0x02
#define  PCI_CB_BRIDGE_CTL_ISA		0x04
#define  PCI_CB_BRIDGE_CTL_VGA		0x08
#define  PCI_CB_BRIDGE_CTL_MASTER_ABORT	0x20
#define  PCI_CB_BRIDGE_CTL_CB_RESET	0x40	/* CardBus reset */
#define  PCI_CB_BRIDGE_CTL_16BIT_INT	0x80	/* Enable interrupt for 16-bit cards */
#define  PCI_CB_BRIDGE_CTL_PREFETCH_MEM0 0x100	/* Prefetch enable for both memory regions */
#define  PCI_CB_BRIDGE_CTL_PREFETCH_MEM1 0x200
#define  PCI_CB_BRIDGE_CTL_POST_WRITES	0x400
#define PCI_CB_SUBSYSTEM_VENDOR_ID	0x40
#define PCI_CB_SUBSYSTEM_ID		0x42
#define PCI_CB_LEGACY_MODE_BASE		0x44	/* 16-bit PC Card legacy mode base address (ExCa) */
/* 0x48-0x7f reserved */

/* Capability lists */

#define PCI_CAP_LIST_ID		0	/* Capability ID */
#define  PCI_CAP_ID_PM		0x01	/* Power Management */
#define  PCI_CAP_ID_AGP		0x02	/* Accelerated Graphics Port */
#define  PCI_CAP_ID_VPD		0x03	/* Vital Product Data */
#define  PCI_CAP_ID_SLOTID	0x04	/* Slot Identification */
#define  PCI_CAP_ID_MSI		0x05	/* Message Signalled Interrupts */
#define  PCI_CAP_ID_CHSWP	0x06	/* CompactPCI HotSwap */
#define  PCI_CAP_ID_PCIX	0x07	/* PCI-X */
#define  PCI_CAP_ID_HT		0x08	/* HyperTransport */
#define  PCI_CAP_ID_VNDR	0x09	/* Vendor specific */
#define  PCI_CAP_ID_DBG		0x0A	/* Debug port */
#define  PCI_CAP_ID_CCRC	0x0B	/* CompactPCI Central Resource Control */
#define  PCI_CAP_ID_SHPC 	0x0C	/* PCI Standard Hot-Plug Controller */
#define  PCI_CAP_ID_SSVID	0x0D	/* Bridge subsystem vendor/device ID */
#define  PCI_CAP_ID_AGP3	0x0E	/* AGP Target PCI-PCI bridge */
#define  PCI_CAP_ID_SECDEV	0x0F	/* Secure Device */
#define  PCI_CAP_ID_EXP 	0x10	/* PCI Express */
#define  PCI_CAP_ID_MSIX	0x11	/* MSI-X */
#define  PCI_CAP_ID_SATA	0x12	/* SATA Data/Index Conf. */
#define  PCI_CAP_ID_AF		0x13	/* PCI Advanced Features */
#define  PCI_CAP_ID_MAX		PCI_CAP_ID_AF
#define PCI_CAP_LIST_NEXT	1	/* Next capability in the list */
#define PCI_CAP_FLAGS		2	/* Capability defined flags (16 bits) */
#define PCI_CAP_SIZEOF		4

/* Power Management Registers */

#define PCI_PM_PMC		2	/* PM Capabilities Register */
#define  PCI_PM_CAP_VER_MASK	0x0007	/* Version */
#define  PCI_PM_CAP_PME_CLOCK	0x0008	/* PME clock required */
#define  PCI_PM_CAP_RESERVED    0x0010  /* Reserved field */
#define  PCI_PM_CAP_DSI		0x0020	/* Device specific initialization */
#define  PCI_PM_CAP_AUX_POWER	0x01C0	/* Auxiliary power support mask */
#define  PCI_PM_CAP_D1		0x0200	/* D1 power state support */
#define  PCI_PM_CAP_D2		0x0400	/* D2 power state support */
#define  PCI_PM_CAP_PME		0x0800	/* PME pin supported */
#define  PCI_PM_CAP_PME_MASK	0xF800	/* PME Mask of all supported states */
#define  PCI_PM_CAP_PME_D0	0x0800	/* PME# from D0 */
#define  PCI_PM_CAP_PME_D1	0x1000	/* PME# from D1 */
#define  PCI_PM_CAP_PME_D2	0x2000	/* PME# from D2 */
#define  PCI_PM_CAP_PME_D3	0x4000	/* PME# from D3 (hot) */
#define  PCI_PM_CAP_PME_D3cold	0x8000	/* PME# from D3 (cold) */
#define  PCI_PM_CAP_PME_SHIFT	11	/* Start of the PME Mask in PMC */
#define PCI_PM_CTRL		4	/* PM control and status register */
#define  PCI_PM_CTRL_STATE_MASK	0x0003	/* Current power state (D0 to D3) */
#define  PCI_PM_CTRL_NO_SOFT_RESET	0x0008	/* No reset for D3hot->D0 */
#define  PCI_PM_CTRL_PME_ENABLE	0x0100	/* PME pin enable */
#define  PCI_PM_CTRL_DATA_SEL_MASK	0x1e00	/* Data select (??) */
#define  PCI_PM_CTRL_DATA_SCALE_MASK	0x6000	/* Data scale (??) */
#define  PCI_PM_CTRL_PME_STATUS	0x8000	/* PME pin status */
#define PCI_PM_PPB_EXTENSIONS	6	/* PPB support extensions (??) */
#define  PCI_PM_PPB_B2_B3	0x40	/* Stop clock when in D3hot (??) */
#define  PCI_PM_BPCC_ENABLE	0x80	/* Bus power/clock control enable (??) */
#define PCI_PM_DATA_REGISTER	7	/* (??) */
#define PCI_PM_SIZEOF		8

/* AGP registers */

#define PCI_AGP_VERSION		2	/* BCD version number */
#define PCI_AGP_RFU		3	/* Rest of capability flags */
#define PCI_AGP_STATUS		4	/* Status register */
#define  PCI_AGP_STATUS_RQ_MASK	0xff000000	/* Maximum number of requests - 1 */
#define  PCI_AGP_STATUS_SBA	0x0200	/* Sideband addressing supported */
#define  PCI_AGP_STATUS_64BIT	0x0020	/* 64-bit addressing supported */
#define  PCI_AGP_STATUS_FW	0x0010	/* FW transfers supported */
#define  PCI_AGP_STATUS_RATE4	0x0004	/* 4x transfer rate supported */
#define  PCI_AGP_STATUS_RATE2	0x0002	/* 2x transfer rate supported */
#define  PCI_AGP_STATUS_RATE1	0x0001	/* 1x transfer rate supported */
#define PCI_AGP_COMMAND		8	/* Control register */
#define  PCI_AGP_COMMAND_RQ_MASK 0xff000000  /* Master: Maximum number of requests */
#define  PCI_AGP_COMMAND_SBA	0x0200	/* Sideband addressing enabled */
#define  PCI_AGP_COMMAND_AGP	0x0100	/* Allow processing of AGP transactions */
#define  PCI_AGP_COMMAND_64BIT	0x0020 	/* Allow processing of 64-bit addresses */
#define  PCI_AGP_COMMAND_FW	0x0010 	/* Force FW transfers */
#define  PCI_AGP_COMMAND_RATE4	0x0004	/* Use 4x rate */
#define  PCI_AGP_COMMAND_RATE2	0x0002	/* Use 2x rate */
#define  PCI_AGP_COMMAND_RATE1	0x0001	/* Use 1x rate */
#define PCI_AGP_SIZEOF		12

/* Vital Product Data */

#define PCI_VPD_ADDR		2	/* Address to access (15 bits!) */
#define  PCI_VPD_ADDR_MASK	0x7fff	/* Address mask */
#define  PCI_VPD_ADDR_F		0x8000	/* Write 0, 1 indicates completion */
#define PCI_VPD_DATA		4	/* 32-bits of data returned here */
#define PCI_CAP_VPD_SIZEOF	8

/* Slot Identification */

#define PCI_SID_ESR		2	/* Expansion Slot Register */
#define  PCI_SID_ESR_NSLOTS	0x1f	/* Number of expansion slots available */
#define  PCI_SID_ESR_FIC	0x20	/* First In Chassis Flag */
#define PCI_SID_CHASSIS_NR	3	/* Chassis Number */

/* Message Signalled Interrupts registers */

#define PCI_MSI_FLAGS		2	/* Message Control */
#define  PCI_MSI_FLAGS_ENABLE	0x0001	/* MSI feature enabled */
#define  PCI_MSI_FLAGS_QMASK	0x000e	/* Maximum queue size available */
#define  PCI_MSI_FLAGS_QSIZE	0x0070	/* Message queue size configured */
#define  PCI_MSI_FLAGS_64BIT	0x0080	/* 64-bit addresses allowed */
#define  PCI_MSI_FLAGS_MASKBIT	0x0100	/* Per-vector masking capable */
#define PCI_MSI_RFU		3	/* Rest of capability flags */
#define PCI_MSI_ADDRESS_LO	4	/* Lower 32 bits */
#define PCI_MSI_ADDRESS_HI	8	/* Upper 32 bits (if PCI_MSI_FLAGS_64BIT set) */
#define PCI_MSI_DATA_32		8	/* 16 bits of data for 32-bit devices */
#define PCI_MSI_MASK_32		12	/* Mask bits register for 32-bit devices */
#define PCI_MSI_PENDING_32	16	/* Pending intrs for 32-bit devices */
#define PCI_MSI_DATA_64		12	/* 16 bits of data for 64-bit devices */
#define PCI_MSI_MASK_64		16	/* Mask bits register for 64-bit devices */
#define PCI_MSI_PENDING_64	20	/* Pending intrs for 64-bit devices */

/* MSI-X registers */
#define PCI_MSIX_FLAGS		2	/* Message Control */
#define  PCI_MSIX_FLAGS_QSIZE	0x07FF	/* Table size */
#define  PCI_MSIX_FLAGS_MASKALL	0x4000	/* Mask all vectors for this function */
#define  PCI_MSIX_FLAGS_ENABLE	0x8000	/* MSI-X enable */
#define PCI_MSIX_TABLE		4	/* Table offset */
#define  PCI_MSIX_TABLE_BIR	0x00000007 /* BAR index */
#define  PCI_MSIX_TABLE_OFFSET	0xfffffff8 /* Offset into specified BAR */
#define PCI_MSIX_PBA		8	/* Pending Bit Array offset */
#define  PCI_MSIX_PBA_BIR	0x00000007 /* BAR index */
#define  PCI_MSIX_PBA_OFFSET	0xfffffff8 /* Offset into specified BAR */
#define  PCI_MSIX_FLAGS_BIRMASK	(7 << 0)   /* deprecated */
#define PCI_CAP_MSIX_SIZEOF	12	/* size of MSIX registers */

/* MSI-X entry's format */
#define PCI_MSIX_ENTRY_SIZE		16
#define  PCI_MSIX_ENTRY_LOWER_ADDR	0
#define  PCI_MSIX_ENTRY_UPPER_ADDR	4
#define  PCI_MSIX_ENTRY_DATA		8
#define  PCI_MSIX_ENTRY_VECTOR_CTRL	12
#define   PCI_MSIX_ENTRY_CTRL_MASKBIT	1

/* CompactPCI Hotswap Register */

#define PCI_CHSWP_CSR		2	/* Control and Status Register */
#define  PCI_CHSWP_DHA		0x01	/* Device Hiding Arm */
#define  PCI_CHSWP_EIM		0x02	/* ENUM# Signal Mask */
#define  PCI_CHSWP_PIE		0x04	/* Pending Insert or Extract */
#define  PCI_CHSWP_LOO		0x08	/* LED On / Off */
#define  PCI_CHSWP_PI		0x30	/* Programming Interface */
#define  PCI_CHSWP_EXT		0x40	/* ENUM# status - extraction */
#define  PCI_CHSWP_INS		0x80	/* ENUM# status - insertion */

/* PCI Advanced Feature registers */

#define PCI_AF_LENGTH		2
#define PCI_AF_CAP		3
#define  PCI_AF_CAP_TP		0x01
#define  PCI_AF_CAP_FLR		0x02
#define PCI_AF_CTRL		4
#define  PCI_AF_CTRL_FLR	0x01
#define PCI_AF_STATUS		5
#define  PCI_AF_STATUS_TP	0x01
#define PCI_CAP_AF_SIZEOF	6	/* size of AF registers */

/* PCI-X registers (Type 0 (non-bridge) devices) */

#define PCI_X_CMD		2	/* Modes & Features */
#define  PCI_X_CMD_DPERR_E	0x0001	/* Data Parity Error Recovery Enable */
#define  PCI_X_CMD_ERO		0x0002	/* Enable Relaxed Ordering */
#define  PCI_X_CMD_READ_512	0x0000	/* 512 byte maximum read byte count */
#define  PCI_X_CMD_READ_1K	0x0004	/* 1Kbyte maximum read byte count */
#define  PCI_X_CMD_READ_2K	0x0008	/* 2Kbyte maximum read byte count */
#define  PCI_X_CMD_READ_4K	0x000c	/* 4Kbyte maximum read byte count */
#define  PCI_X_CMD_MAX_READ	0x000c	/* Max Memory Read Byte Count */
				/* Max # of outstanding split transactions */
#define  PCI_X_CMD_SPLIT_1	0x0000	/* Max 1 */
#define  PCI_X_CMD_SPLIT_2	0x0010	/* Max 2 */
#define  PCI_X_CMD_SPLIT_3	0x0020	/* Max 3 */
#define  PCI_X_CMD_SPLIT_4	0x0030	/* Max 4 */
#define  PCI_X_CMD_SPLIT_8	0x0040	/* Max 8 */
#define  PCI_X_CMD_SPLIT_12	0x0050	/* Max 12 */
#define  PCI_X_CMD_SPLIT_16	0x0060	/* Max 16 */
#define  PCI_X_CMD_SPLIT_32	0x0070	/* Max 32 */
#define  PCI_X_CMD_MAX_SPLIT	0x0070	/* Max Outstanding Split Transactions */
#define  PCI_X_CMD_VERSION(x) 	(((x) >> 12) & 3) /* Version */
#define PCI_X_STATUS		4	/* PCI-X capabilities */
#define  PCI_X_STATUS_DEVFN	0x000000ff	/* A copy of devfn */
#define  PCI_X_STATUS_BUS	0x0000ff00	/* A copy of bus nr */
#define  PCI_X_STATUS_64BIT	0x00010000	/* 64-bit device */
#define  PCI_X_STATUS_133MHZ	0x00020000	/* 133 MHz capable */
#define  PCI_X_STATUS_SPL_DISC	0x00040000	/* Split Completion Discarded */
#define  PCI_X_STATUS_UNX_SPL	0x00080000	/* Unexpected Split Completion */
#define  PCI_X_STATUS_COMPLEX	0x00100000	/* Device Complexity */
#define  PCI_X_STATUS_MAX_READ	0x00600000	/* Designed Max Memory Read Count */
#define  PCI_X_STATUS_MAX_SPLIT	0x03800000	/* Designed Max Outstanding Split Transactions */
#define  PCI_X_STATUS_MAX_CUM	0x1c000000	/* Designed Max Cumulative Read Size */
#define  PCI_X_STATUS_SPL_ERR	0x20000000	/* Rcvd Split Completion Error Msg */
#define  PCI_X_STATUS_266MHZ	0x40000000	/* 266 MHz capable */
#define  PCI_X_STATUS_533MHZ	0x80000000	/* 533 MHz capable */
#define PCI_X_ECC_CSR		8	/* ECC control and status */
#define PCI_CAP_PCIX_SIZEOF_V0	8	/* size of registers for Version 0 */
#define PCI_CAP_PCIX_SIZEOF_V1	24	/* size for Version 1 */
#define PCI_CAP_PCIX_SIZEOF_V2	PCI_CAP_PCIX_SIZEOF_V1	/* Same for v2 */

/* PCI-X registers (Type 1 (bridge) devices) */

#define PCI_X_BRIDGE_SSTATUS	2	/* Secondary Status */
#define  PCI_X_SSTATUS_64BIT	0x0001	/* Secondary AD interface is 64 bits */
#define  PCI_X_SSTATUS_133MHZ	0x0002	/* 133 MHz capable */
#define  PCI_X_SSTATUS_FREQ	0x03c0	/* Secondary Bus Mode and Frequency */
#define  PCI_X_SSTATUS_VERS	0x3000	/* PCI-X Capability Version */
#define  PCI_X_SSTATUS_V1	0x1000	/* Mode 2, not Mode 1 */
#define  PCI_X_SSTATUS_V2	0x2000	/* Mode 1 or Modes 1 and 2 */
#define  PCI_X_SSTATUS_266MHZ	0x4000	/* 266 MHz capable */
#define  PCI_X_SSTATUS_533MHZ	0x8000	/* 533 MHz capable */
#define PCI_X_BRIDGE_STATUS	4	/* Bridge Status */

/* PCI Bridge Subsystem ID registers */

#define PCI_SSVID_VENDOR_ID     4	/* PCI-Bridge subsystem vendor id register */
#define PCI_SSVID_DEVICE_ID     6	/* PCI-Bridge subsystem device id register */

/* PCI Express capability registers */

#define PCI_EXP_FLAGS		2	/* Capabilities register */
#define PCI_EXP_FLAGS_VERS	0x000f	/* Capability version */
#define PCI_EXP_FLAGS_TYPE	0x00f0	/* Device/Port type */
#define  PCI_EXP_TYPE_ENDPOINT	0x0	/* Express Endpoint */
#define  PCI_EXP_TYPE_LEG_END	0x1	/* Legacy Endpoint */
#define  PCI_EXP_TYPE_ROOT_PORT 0x4	/* Root Port */
#define  PCI_EXP_TYPE_UPSTREAM	0x5	/* Upstream Port */
#define  PCI_EXP_TYPE_DOWNSTREAM 0x6	/* Downstream Port */
#define  PCI_EXP_TYPE_PCI_BRIDGE 0x7	/* PCI/PCI-X Bridge */
#define  PCI_EXP_TYPE_PCIE_BRIDGE 0x8	/* PCI/PCI-X to PCIE Bridge */
#define  PCI_EXP_TYPE_RC_END	0x9	/* Root Complex Integrated Endpoint */
#define  PCI_EXP_TYPE_RC_EC	0xa	/* Root Complex Event Collector */
#define PCI_EXP_FLAGS_SLOT	0x0100	/* Slot implemented */
#define PCI_EXP_FLAGS_IRQ	0x3e00	/* Interrupt message number */
#define PCI_EXP_DEVCAP		4	/* Device capabilities */
#define  PCI_EXP_DEVCAP_PAYLOAD	0x07	/* Max_Payload_Size */
#define  PCI_EXP_DEVCAP_PHANTOM	0x18	/* Phantom functions */
#define  PCI_EXP_DEVCAP_EXT_TAG	0x20	/* Extended tags */
#define  PCI_EXP_DEVCAP_L0S	0x1c0	/* L0s Acceptable Latency */
#define  PCI_EXP_DEVCAP_L1	0xe00	/* L1 Acceptable Latency */
#define  PCI_EXP_DEVCAP_ATN_BUT	0x1000	/* Attention Button Present */
#define  PCI_EXP_DEVCAP_ATN_IND	0x2000	/* Attention Indicator Present */
#define  PCI_EXP_DEVCAP_PWR_IND	0x4000	/* Power Indicator Present */
#define  PCI_EXP_DEVCAP_RBER	0x8000	/* Role-Based Error Reporting */
#define  PCI_EXP_DEVCAP_PWR_VAL	0x3fc0000 /* Slot Power Limit Value */
#define  PCI_EXP_DEVCAP_PWR_SCL	0xc000000 /* Slot Power Limit Scale */
#define  PCI_EXP_DEVCAP_FLR     0x10000000 /* Function Level Reset */
#define PCI_EXP_DEVCTL		8	/* Device Control */
#define  PCI_EXP_DEVCTL_CERE	0x0001	/* Correctable Error Reporting En. */
#define  PCI_EXP_DEVCTL_NFERE	0x0002	/* Non-Fatal Error Reporting Enable */
#define  PCI_EXP_DEVCTL_FERE	0x0004	/* Fatal Error Reporting Enable */
#define  PCI_EXP_DEVCTL_URRE	0x0008	/* Unsupported Request Reporting En. */
#define  PCI_EXP_DEVCTL_RELAX_EN 0x0010 /* Enable relaxed ordering */
#define  PCI_EXP_DEVCTL_PAYLOAD	0x00e0	/* Max_Payload_Size */
#define  PCI_EXP_DEVCTL_EXT_TAG	0x0100	/* Extended Tag Field Enable */
#define  PCI_EXP_DEVCTL_PHANTOM	0x0200	/* Phantom Functions Enable */
#define  PCI_EXP_DEVCTL_AUX_PME	0x0400	/* Auxiliary Power PM Enable */
#define  PCI_EXP_DEVCTL_NOSNOOP_EN 0x0800  /* Enable No Snoop */
#define  PCI_EXP_DEVCTL_READRQ	0x7000	/* Max_Read_Request_Size */
#define  PCI_EXP_DEVCTL_BCR_FLR 0x8000  /* Bridge Configuration Retry / FLR */
#define PCI_EXP_DEVSTA		10	/* Device Status */
#define  PCI_EXP_DEVSTA_CED	0x01	/* Correctable Error Detected */
#define  PCI_EXP_DEVSTA_NFED	0x02	/* Non-Fatal Error Detected */
#define  PCI_EXP_DEVSTA_FED	0x04	/* Fatal Error Detected */
#define  PCI_EXP_DEVSTA_URD	0x08	/* Unsupported Request Detected */
#define  PCI_EXP_DEVSTA_AUXPD	0x10	/* AUX Power Detected */
#define  PCI_EXP_DEVSTA_TRPND	0x20	/* Transactions Pending */
#define PCI_EXP_LNKCAP		12	/* Link Capabilities */
#define  PCI_EXP_LNKCAP_SLS	0x0000000f /* Supported Link Speeds */
#define  PCI_EXP_LNKCAP_SLS_2_5GB 0x1	/* LNKCAP2 SLS Vector bit 0 (2.5GT/s) */
#define  PCI_EXP_LNKCAP_SLS_5_0GB 0x2	/* LNKCAP2 SLS Vector bit 1 (5.0GT/s) */
#define  PCI_EXP_LNKCAP_MLW	0x000003f0 /* Maximum Link Width */
#define  PCI_EXP_LNKCAP_ASPMS	0x00000c00 /* ASPM Support */
#define  PCI_EXP_LNKCAP_L0SEL	0x00007000 /* L0s Exit Latency */
#define  PCI_EXP_LNKCAP_L1EL	0x00038000 /* L1 Exit Latency */
#define  PCI_EXP_LNKCAP_CLKPM	0x00040000 /* Clock Power Management */
#define  PCI_EXP_LNKCAP_SDERC	0x00080000 /* Surprise Down Error Reporting Capable */
#define  PCI_EXP_LNKCAP_DLLLARC	0x00100000 /* Data Link Layer Link Active Reporting Capable */
#define  PCI_EXP_LNKCAP_LBNC	0x00200000 /* Link Bandwidth Notification Capability */
#define  PCI_EXP_LNKCAP_PN	0xff000000 /* Port Number */
#define PCI_EXP_LNKCTL		16	/* Link Control */
#define  PCI_EXP_LNKCTL_ASPMC	0x0003	/* ASPM Control */
#define  PCI_EXP_LNKCTL_ASPM_L0S  0x01	/* L0s Enable */
#define  PCI_EXP_LNKCTL_ASPM_L1   0x02	/* L1 Enable */
#define  PCI_EXP_LNKCTL_RCB	0x0008	/* Read Completion Boundary */
#define  PCI_EXP_LNKCTL_LD	0x0010	/* Link Disable */
#define  PCI_EXP_LNKCTL_RL	0x0020	/* Retrain Link */
#define  PCI_EXP_LNKCTL_CCC	0x0040	/* Common Clock Configuration */
#define  PCI_EXP_LNKCTL_ES	0x0080	/* Extended Synch */
#define  PCI_EXP_LNKCTL_CLKREQ_EN 0x100	/* Enable clkreq */
#define  PCI_EXP_LNKCTL_HAWD	0x0200	/* Hardware Autonomous Width Disable */
#define  PCI_EXP_LNKCTL_LBMIE	0x0400	/* Link Bandwidth Management Interrupt Enable */
#define  PCI_EXP_LNKCTL_LABIE	0x0800	/* Lnk Autonomous Bandwidth Interrupt Enable */
#define PCI_EXP_LNKSTA		18	/* Link Status */
#define  PCI_EXP_LNKSTA_CLS	0x000f	/* Current Link Speed */
#define  PCI_EXP_LNKSTA_CLS_2_5GB 0x01	/* Current Link Speed 2.5GT/s */
#define  PCI_EXP_LNKSTA_CLS_5_0GB 0x02	/* Current Link Speed 5.0GT/s */
#define  PCI_EXP_LNKSTA_NLW	0x03f0	/* Nogotiated Link Width */
#define  PCI_EXP_LNKSTA_NLW_SHIFT 4	/* start of NLW mask in link status */
#define  PCI_EXP_LNKSTA_LT	0x0800	/* Link Training */
#define  PCI_EXP_LNKSTA_SLC	0x1000	/* Slot Clock Configuration */
#define  PCI_EXP_LNKSTA_DLLLA	0x2000	/* Data Link Layer Link Active */
#define  PCI_EXP_LNKSTA_LBMS	0x4000	/* Link Bandwidth Management Status */
#define  PCI_EXP_LNKSTA_LABS	0x8000	/* Link Autonomous Bandwidth Status */
#define PCI_CAP_EXP_ENDPOINT_SIZEOF_V1	20	/* v1 endpoints end here */
#define PCI_EXP_SLTCAP		20	/* Slot Capabilities */
#define  PCI_EXP_SLTCAP_ABP	0x00000001 /* Attention Button Present */
#define  PCI_EXP_SLTCAP_PCP	0x00000002 /* Power Controller Present */
#define  PCI_EXP_SLTCAP_MRLSP	0x00000004 /* MRL Sensor Present */
#define  PCI_EXP_SLTCAP_AIP	0x00000008 /* Attention Indicator Present */
#define  PCI_EXP_SLTCAP_PIP	0x00000010 /* Power Indicator Present */
#define  PCI_EXP_SLTCAP_HPS	0x00000020 /* Hot-Plug Surprise */
#define  PCI_EXP_SLTCAP_HPC	0x00000040 /* Hot-Plug Capable */
#define  PCI_EXP_SLTCAP_SPLV	0x00007f80 /* Slot Power Limit Value */
#define  PCI_EXP_SLTCAP_SPLS	0x00018000 /* Slot Power Limit Scale */
#define  PCI_EXP_SLTCAP_EIP	0x00020000 /* Electromechanical Interlock Present */
#define  PCI_EXP_SLTCAP_NCCS	0x00040000 /* No Command Completed Support */
#define  PCI_EXP_SLTCAP_PSN	0xfff80000 /* Physical Slot Number */
#define PCI_EXP_SLTCTL		24	/* Slot Control */
#define  PCI_EXP_SLTCTL_ABPE	0x0001	/* Attention Button Pressed Enable */
#define  PCI_EXP_SLTCTL_PFDE	0x0002	/* Power Fault Detected Enable */
#define  PCI_EXP_SLTCTL_MRLSCE	0x0004	/* MRL Sensor Changed Enable */
#define  PCI_EXP_SLTCTL_PDCE	0x0008	/* Presence Detect Changed Enable */
#define  PCI_EXP_SLTCTL_CCIE	0x0010	/* Command Completed Interrupt Enable */
#define  PCI_EXP_SLTCTL_HPIE	0x0020	/* Hot-Plug Interrupt Enable */
#define  PCI_EXP_SLTCTL_AIC	0x00c0	/* Attention Indicator Control */
#define  PCI_EXP_SLTCTL_PIC	0x0300	/* Power Indicator Control */
#define  PCI_EXP_SLTCTL_PCC	0x0400	/* Power Controller Control */
#define  PCI_EXP_SLTCTL_EIC	0x0800	/* Electromechanical Interlock Control */
#define  PCI_EXP_SLTCTL_DLLSCE	0x1000	/* Data Link Layer State Changed Enable */
#define PCI_EXP_SLTSTA		26	/* Slot Status */
#define  PCI_EXP_SLTSTA_ABP	0x0001	/* Attention Button Pressed */
#define  PCI_EXP_SLTSTA_PFD	0x0002	/* Power Fault Detected */
#define  PCI_EXP_SLTSTA_MRLSC	0x0004	/* MRL Sensor Changed */
#define  PCI_EXP_SLTSTA_PDC	0x0008	/* Presence Detect Changed */
#define  PCI_EXP_SLTSTA_CC	0x0010	/* Command Completed */
#define  PCI_EXP_SLTSTA_MRLSS	0x0020	/* MRL Sensor State */
#define  PCI_EXP_SLTSTA_PDS	0x0040	/* Presence Detect State */
#define  PCI_EXP_SLTSTA_EIS	0x0080	/* Electromechanical Interlock Status */
#define  PCI_EXP_SLTSTA_DLLSC	0x0100	/* Data Link Layer State Changed */
#define PCI_EXP_RTCTL		28	/* Root Control */
#define  PCI_EXP_RTCTL_SECEE	0x01	/* System Error on Correctable Error */
#define  PCI_EXP_RTCTL_SENFEE	0x02	/* System Error on Non-Fatal Error */
#define  PCI_EXP_RTCTL_SEFEE	0x04	/* System Error on Fatal Error */
#define  PCI_EXP_RTCTL_PMEIE	0x08	/* PME Interrupt Enable */
#define  PCI_EXP_RTCTL_CRSSVE	0x10	/* CRS Software Visibility Enable */
#define PCI_EXP_RTCAP		30	/* Root Capabilities */
#define PCI_EXP_RTSTA		32	/* Root Status */
#define PCI_EXP_RTSTA_PME	0x10000 /* PME status */
#define PCI_EXP_RTSTA_PENDING	0x20000 /* PME pending */
/*
 * Note that the following PCI Express 'Capability Structure' registers
 * were introduced with 'Capability Version' 0x2 (v2).  These registers
 * do not exist on devices with Capability Version 1.  Use pci_pcie_cap2()
 * to use these fields safely.
 */
#define PCI_EXP_DEVCAP2		36	/* Device Capabilities 2 */
#define  PCI_EXP_DEVCAP2_ARI	0x20	/* Alternative Routing-ID */
#define  PCI_EXP_DEVCAP2_LTR	0x800	/* Latency tolerance reporting */
#define  PCI_EXP_OBFF_MASK	0xc0000 /* OBFF support mechanism */
#define  PCI_EXP_OBFF_MSG	0x40000 /* New message signaling */
#define  PCI_EXP_OBFF_WAKE	0x80000 /* Re-use WAKE# for OBFF */
#define PCI_EXP_DEVCTL2		40	/* Device Control 2 */
#define  PCI_EXP_DEVCTL2_ARI	0x20	/* Alternative Routing-ID */
#define  PCI_EXP_IDO_REQ_EN	0x100	/* ID-based ordering request enable */
#define  PCI_EXP_IDO_CMP_EN	0x200	/* ID-based ordering completion enable */
#define  PCI_EXP_LTR_EN		0x400	/* Latency tolerance reporting */
#define  PCI_EXP_OBFF_MSGA_EN	0x2000	/* OBFF enable with Message type A */
#define  PCI_EXP_OBFF_MSGB_EN	0x4000	/* OBFF enable with Message type B */
#define  PCI_EXP_OBFF_WAKE_EN	0x6000	/* OBFF using WAKE# signaling */
#define PCI_CAP_EXP_ENDPOINT_SIZEOF_V2	44	/* v2 endpoints end here */
#define PCI_EXP_LNKCAP2		44	/* Link Capability 2 */
#define  PCI_EXP_LNKCAP2_SLS_2_5GB 0x02	/* Supported Link Speed 2.5GT/s */
#define  PCI_EXP_LNKCAP2_SLS_5_0GB 0x04	/* Supported Link Speed 5.0GT/s */
#define  PCI_EXP_LNKCAP2_SLS_8_0GB 0x08	/* Supported Link Speed 8.0GT/s */
#define  PCI_EXP_LNKCAP2_CROSSLINK 0x100 /* Crosslink supported */
#define PCI_EXP_LNKCTL2		48	/* Link Control 2 */
#define PCI_EXP_LNKSTA2		50	/* Link Status 2 */
#define PCI_EXP_SLTCTL2		56	/* Slot Control 2 */

/* Extended Capabilities (PCI-X 2.0 and Express) */
#define PCI_EXT_CAP_ID(header)		(header & 0x0000ffff)
#define PCI_EXT_CAP_VER(header)		((header >> 16) & 0xf)
#define PCI_EXT_CAP_NEXT(header)	((header >> 20) & 0xffc)

#define PCI_EXT_CAP_ID_ERR	0x01	/* Advanced Error Reporting */
#define PCI_EXT_CAP_ID_VC	0x02	/* Virtual Channel Capability */
#define PCI_EXT_CAP_ID_DSN	0x03	/* Device Serial Number */
#define PCI_EXT_CAP_ID_PWR	0x04	/* Power Budgeting */
#define PCI_EXT_CAP_ID_RCLD	0x05	/* Root Complex Link Declaration */
#define PCI_EXT_CAP_ID_RCILC	0x06	/* Root Complex Internal Link Control */
#define PCI_EXT_CAP_ID_RCEC	0x07	/* Root Complex Event Collector */
#define PCI_EXT_CAP_ID_MFVC	0x08	/* Multi-Function VC Capability */
#define PCI_EXT_CAP_ID_VC9	0x09	/* same as _VC */
#define PCI_EXT_CAP_ID_RCRB	0x0A	/* Root Complex RB? */
#define PCI_EXT_CAP_ID_VNDR	0x0B	/* Vendor Specific */
#define PCI_EXT_CAP_ID_CAC	0x0C	/* Config Access - obsolete */
#define PCI_EXT_CAP_ID_ACS	0x0D	/* Access Control Services */
#define PCI_EXT_CAP_ID_ARI	0x0E	/* Alternate Routing ID */
#define PCI_EXT_CAP_ID_ATS	0x0F	/* Address Translation Services */
#define PCI_EXT_CAP_ID_SRIOV	0x10	/* Single Root I/O Virtualization */
#define PCI_EXT_CAP_ID_MRIOV	0x11	/* Multi Root I/O Virtualization */
#define PCI_EXT_CAP_ID_MCAST	0x12	/* Multicast */
#define PCI_EXT_CAP_ID_PRI	0x13	/* Page Request Interface */
#define PCI_EXT_CAP_ID_AMD_XXX	0x14	/* reserved for AMD */
#define PCI_EXT_CAP_ID_REBAR	0x15	/* resizable BAR */
#define PCI_EXT_CAP_ID_DPA	0x16	/* dynamic power alloc */
#define PCI_EXT_CAP_ID_TPH	0x17	/* TPH request */
#define PCI_EXT_CAP_ID_LTR	0x18	/* latency tolerance reporting */
#define PCI_EXT_CAP_ID_SECPCI	0x19	/* Secondary PCIe */
#define PCI_EXT_CAP_ID_PMUX	0x1A	/* Protocol Multiplexing */
#define PCI_EXT_CAP_ID_PASID	0x1B	/* Process Address Space ID */
#define PCI_EXT_CAP_ID_MAX	PCI_EXT_CAP_ID_PASID

#define PCI_EXT_CAP_DSN_SIZEOF	12
#define PCI_EXT_CAP_MCAST_ENDPOINT_SIZEOF 40

/* Advanced Error Reporting */
#define PCI_ERR_UNCOR_STATUS	4	/* Uncorrectable Error Status */
#define  PCI_ERR_UNC_TRAIN	0x00000001	/* Training */
#define  PCI_ERR_UNC_DLP	0x00000010	/* Data Link Protocol */
#define  PCI_ERR_UNC_SURPDN	0x00000020	/* Surprise Down */
#define  PCI_ERR_UNC_POISON_TLP	0x00001000	/* Poisoned TLP */
#define  PCI_ERR_UNC_FCP	0x00002000	/* Flow Control Protocol */
#define  PCI_ERR_UNC_COMP_TIME	0x00004000	/* Completion Timeout */
#define  PCI_ERR_UNC_COMP_ABORT	0x00008000	/* Completer Abort */
#define  PCI_ERR_UNC_UNX_COMP	0x00010000	/* Unexpected Completion */
#define  PCI_ERR_UNC_RX_OVER	0x00020000	/* Receiver Overflow */
#define  PCI_ERR_UNC_MALF_TLP	0x00040000	/* Malformed TLP */
#define  PCI_ERR_UNC_ECRC	0x00080000	/* ECRC Error Status */
#define  PCI_ERR_UNC_UNSUP	0x00100000	/* Unsupported Request */
#define  PCI_ERR_UNC_ACSV	0x00200000	/* ACS Violation */
#define  PCI_ERR_UNC_INTN	0x00400000	/* internal error */
#define  PCI_ERR_UNC_MCBTLP	0x00800000	/* MC blocked TLP */
#define  PCI_ERR_UNC_ATOMEG	0x01000000	/* Atomic egress blocked */
#define  PCI_ERR_UNC_TLPPRE	0x02000000	/* TLP prefix blocked */
#define PCI_ERR_UNCOR_MASK	8	/* Uncorrectable Error Mask */
	/* Same bits as above */
#define PCI_ERR_UNCOR_SEVER	12	/* Uncorrectable Error Severity */
	/* Same bits as above */
#define PCI_ERR_COR_STATUS	16	/* Correctable Error Status */
#define  PCI_ERR_COR_RCVR	0x00000001	/* Receiver Error Status */
#define  PCI_ERR_COR_BAD_TLP	0x00000040	/* Bad TLP Status */
#define  PCI_ERR_COR_BAD_DLLP	0x00000080	/* Bad DLLP Status */
#define  PCI_ERR_COR_REP_ROLL	0x00000100	/* REPLAY_NUM Rollover */
#define  PCI_ERR_COR_REP_TIMER	0x00001000	/* Replay Timer Timeout */
#define  PCI_ERR_COR_ADV_NFAT	0x00002000	/* Advisory Non-Fatal */
#define  PCI_ERR_COR_INTERNAL	0x00004000	/* Corrected Internal */
#define  PCI_ERR_COR_LOG_OVER	0x00008000	/* Header Log Overflow */
#define PCI_ERR_COR_MASK	20	/* Correctable Error Mask */
	/* Same bits as above */
#define PCI_ERR_CAP		24	/* Advanced Error Capabilities */
#define  PCI_ERR_CAP_FEP(x)	((x) & 31)	/* First Error Pointer */
#define  PCI_ERR_CAP_ECRC_GENC	0x00000020	/* ECRC Generation Capable */
#define  PCI_ERR_CAP_ECRC_GENE	0x00000040	/* ECRC Generation Enable */
#define  PCI_ERR_CAP_ECRC_CHKC	0x00000080	/* ECRC Check Capable */
#define  PCI_ERR_CAP_ECRC_CHKE	0x00000100	/* ECRC Check Enable */
#define PCI_ERR_HEADER_LOG	28	/* Header Log Register (16 bytes) */
#define PCI_ERR_ROOT_COMMAND	44	/* Root Error Command */
/* Correctable Err Reporting Enable */
#define PCI_ERR_ROOT_CMD_COR_EN		0x00000001
/* Non-fatal Err Reporting Enable */
#define PCI_ERR_ROOT_CMD_NONFATAL_EN	0x00000002
/* Fatal Err Reporting Enable */
#define PCI_ERR_ROOT_CMD_FATAL_EN	0x00000004
#define PCI_ERR_ROOT_STATUS	48
#define PCI_ERR_ROOT_COR_RCV		0x00000001	/* ERR_COR Received */
/* Multi ERR_COR Received */
#define PCI_ERR_ROOT_MULTI_COR_RCV	0x00000002
/* ERR_FATAL/NONFATAL Recevied */
#define PCI_ERR_ROOT_UNCOR_RCV		0x00000004
/* Multi ERR_FATAL/NONFATAL Recevied */
#define PCI_ERR_ROOT_MULTI_UNCOR_RCV	0x00000008
#define PCI_ERR_ROOT_FIRST_FATAL	0x00000010	/* First Fatal */
#define PCI_ERR_ROOT_NONFATAL_RCV	0x00000020	/* Non-Fatal Received */
#define PCI_ERR_ROOT_FATAL_RCV		0x00000040	/* Fatal Received */
#define PCI_ERR_ROOT_ERR_SRC	52	/* Error Source Identification */

/* Virtual Channel */
#define PCI_VC_PORT_REG1	4
#define  PCI_VC_REG1_EVCC	0x7	/* extended vc count */
#define PCI_VC_PORT_REG2	8
#define  PCI_VC_REG2_32_PHASE	0x2
#define  PCI_VC_REG2_64_PHASE	0x4
#define  PCI_VC_REG2_128_PHASE	0x8
#define PCI_VC_PORT_CTRL	12
#define PCI_VC_PORT_STATUS	14
#define PCI_VC_RES_CAP		16
#define PCI_VC_RES_CTRL		20
#define PCI_VC_RES_STATUS	26
#define PCI_CAP_VC_BASE_SIZEOF		0x10
#define PCI_CAP_VC_PER_VC_SIZEOF	0x0C

/* Power Budgeting */
#define PCI_PWR_DSR		4	/* Data Select Register */
#define PCI_PWR_DATA		8	/* Data Register */
#define  PCI_PWR_DATA_BASE(x)	((x) & 0xff)	    /* Base Power */
#define  PCI_PWR_DATA_SCALE(x)	(((x) >> 8) & 3)    /* Data Scale */
#define  PCI_PWR_DATA_PM_SUB(x)	(((x) >> 10) & 7)   /* PM Sub State */
#define  PCI_PWR_DATA_PM_STATE(x) (((x) >> 13) & 3) /* PM State */
#define  PCI_PWR_DATA_TYPE(x)	(((x) >> 15) & 7)   /* Type */
#define  PCI_PWR_DATA_RAIL(x)	(((x) >> 18) & 7)   /* Power Rail */
#define PCI_PWR_CAP		12	/* Capability */
#define  PCI_PWR_CAP_BUDGET(x)	((x) & 1)	/* Included in system budget */
#define PCI_EXT_CAP_PWR_SIZEOF	16

/* Vendor-Specific (VSEC, PCI_EXT_CAP_ID_VNDR) */
#define PCI_VNDR_HEADER		4	/* Vendor-Specific Header */
#define  PCI_VNDR_HEADER_ID(x)	((x) & 0xffff)
#define  PCI_VNDR_HEADER_REV(x)	(((x) >> 16) & 0xf)
#define  PCI_VNDR_HEADER_LEN(x)	(((x) >> 20) & 0xfff)

/*
 * Hypertransport sub capability types
 *
 * Unfortunately there are both 3 bit and 5 bit capability types defined
 * in the HT spec, catering for that is a little messy. You probably don't
 * want to use these directly, just use pci_find_ht_capability() and it
 * will do the right thing for you.
 */
#define HT_3BIT_CAP_MASK	0xE0
#define HT_CAPTYPE_SLAVE	0x00	/* Slave/Primary link configuration */
#define HT_CAPTYPE_HOST		0x20	/* Host/Secondary link configuration */

#define HT_5BIT_CAP_MASK	0xF8
#define HT_CAPTYPE_IRQ		0x80	/* IRQ Configuration */
#define HT_CAPTYPE_REMAPPING_40	0xA0	/* 40 bit address remapping */
#define HT_CAPTYPE_REMAPPING_64 0xA2	/* 64 bit address remapping */
#define HT_CAPTYPE_UNITID_CLUMP	0x90	/* Unit ID clumping */
#define HT_CAPTYPE_EXTCONF	0x98	/* Extended Configuration Space Access */
#define HT_CAPTYPE_MSI_MAPPING	0xA8	/* MSI Mapping Capability */
#define  HT_MSI_FLAGS		0x02		/* Offset to flags */
#define  HT_MSI_FLAGS_ENABLE	0x1		/* Mapping enable */
#define  HT_MSI_FLAGS_FIXED	0x2		/* Fixed mapping only */
#define  HT_MSI_FIXED_ADDR	0x00000000FEE00000ULL	/* Fixed addr */
#define  HT_MSI_ADDR_LO		0x04		/* Offset to low addr bits */
#define  HT_MSI_ADDR_LO_MASK	0xFFF00000	/* Low address bit mask */
#define  HT_MSI_ADDR_HI		0x08		/* Offset to high addr bits */
#define HT_CAPTYPE_DIRECT_ROUTE	0xB0	/* Direct routing configuration */
#define HT_CAPTYPE_VCSET	0xB8	/* Virtual Channel configuration */
#define HT_CAPTYPE_ERROR_RETRY	0xC0	/* Retry on error configuration */
#define HT_CAPTYPE_GEN3		0xD0	/* Generation 3 hypertransport configuration */
#define HT_CAPTYPE_PM		0xE0	/* Hypertransport powermanagement configuration */
#define HT_CAP_SIZEOF_LONG	28	/* slave & primary */
#define HT_CAP_SIZEOF_SHORT	24	/* host & secondary */

/* Alternative Routing-ID Interpretation */
#define PCI_ARI_CAP		0x04	/* ARI Capability Register */
#define  PCI_ARI_CAP_MFVC	0x0001	/* MFVC Function Groups Capability */
#define  PCI_ARI_CAP_ACS	0x0002	/* ACS Function Groups Capability */
#define  PCI_ARI_CAP_NFN(x)	(((x) >> 8) & 0xff) /* Next Function Number */
#define PCI_ARI_CTRL		0x06	/* ARI Control Register */
#define  PCI_ARI_CTRL_MFVC	0x0001	/* MFVC Function Groups Enable */
#define  PCI_ARI_CTRL_ACS	0x0002	/* ACS Function Groups Enable */
#define  PCI_ARI_CTRL_FG(x)	(((x) >> 4) & 7) /* Function Group */
#define PCI_EXT_CAP_ARI_SIZEOF	8

/* Address Translation Service */
#define PCI_ATS_CAP		0x04	/* ATS Capability Register */
#define  PCI_ATS_CAP_QDEP(x)	((x) & 0x1f)	/* Invalidate Queue Depth */
#define  PCI_ATS_MAX_QDEP	32	/* Max Invalidate Queue Depth */
#define PCI_ATS_CTRL		0x06	/* ATS Control Register */
#define  PCI_ATS_CTRL_ENABLE	0x8000	/* ATS Enable */
#define  PCI_ATS_CTRL_STU(x)	((x) & 0x1f)	/* Smallest Translation Unit */
#define  PCI_ATS_MIN_STU	12	/* shift of minimum STU block */
#define PCI_EXT_CAP_ATS_SIZEOF	8

/* Page Request Interface */
#define PCI_PRI_CTRL		0x04	/* PRI control register */
#define  PCI_PRI_CTRL_ENABLE	0x01	/* Enable */
#define  PCI_PRI_CTRL_RESET	0x02	/* Reset */
#define PCI_PRI_STATUS		0x06	/* PRI status register */
#define  PCI_PRI_STATUS_RF	0x001	/* Response Failure */
#define  PCI_PRI_STATUS_UPRGI	0x002	/* Unexpected PRG index */
#define  PCI_PRI_STATUS_STOPPED	0x100	/* PRI Stopped */
#define PCI_PRI_MAX_REQ		0x08	/* PRI max reqs supported */
#define PCI_PRI_ALLOC_REQ	0x0c	/* PRI max reqs allowed */
#define PCI_EXT_CAP_PRI_SIZEOF	16

/* PASID capability */
#define PCI_PASID_CAP		0x04    /* PASID feature register */
#define  PCI_PASID_CAP_EXEC	0x02	/* Exec permissions Supported */
#define  PCI_PASID_CAP_PRIV	0x04	/* Priviledge Mode Supported */
#define PCI_PASID_CTRL		0x06    /* PASID control register */
#define  PCI_PASID_CTRL_ENABLE	0x01	/* Enable bit */
#define  PCI_PASID_CTRL_EXEC	0x02	/* Exec permissions Enable */
#define  PCI_PASID_CTRL_PRIV	0x04	/* Priviledge Mode Enable */
#define PCI_EXT_CAP_PASID_SIZEOF	8

/* Single Root I/O Virtualization */
#define PCI_SRIOV_CAP		0x04	/* SR-IOV Capabilities */
#define  PCI_SRIOV_CAP_VFM	0x01	/* VF Migration Capable */
#define  PCI_SRIOV_CAP_INTR(x)	((x) >> 21) /* Interrupt Message Number */
#define PCI_SRIOV_CTRL		0x08	/* SR-IOV Control */
#define  PCI_SRIOV_CTRL_VFE	0x01	/* VF Enable */
#define  PCI_SRIOV_CTRL_VFM	0x02	/* VF Migration Enable */
#define  PCI_SRIOV_CTRL_INTR	0x04	/* VF Migration Interrupt Enable */
#define  PCI_SRIOV_CTRL_MSE	0x08	/* VF Memory Space Enable */
#define  PCI_SRIOV_CTRL_ARI	0x10	/* ARI Capable Hierarchy */
#define PCI_SRIOV_STATUS	0x0a	/* SR-IOV Status */
#define  PCI_SRIOV_STATUS_VFM	0x01	/* VF Migration Status */
#define PCI_SRIOV_INITIAL_VF	0x0c	/* Initial VFs */
#define PCI_SRIOV_TOTAL_VF	0x0e	/* Total VFs */
#define PCI_SRIOV_NUM_VF	0x10	/* Number of VFs */
#define PCI_SRIOV_FUNC_LINK	0x12	/* Function Dependency Link */
#define PCI_SRIOV_VF_OFFSET	0x14	/* First VF Offset */
#define PCI_SRIOV_VF_STRIDE	0x16	/* Following VF Stride */
#define PCI_SRIOV_VF_DID	0x1a	/* VF Device ID */
#define PCI_SRIOV_SUP_PGSIZE	0x1c	/* Supported Page Sizes */
#define PCI_SRIOV_SYS_PGSIZE	0x20	/* System Page Size */
#define PCI_SRIOV_BAR		0x24	/* VF BAR0 */
#define  PCI_SRIOV_NUM_BARS	6	/* Number of VF BARs */
#define PCI_SRIOV_VFM		0x3c	/* VF Migration State Array Offset*/
#define  PCI_SRIOV_VFM_BIR(x)	((x) & 7)	/* State BIR */
#define  PCI_SRIOV_VFM_OFFSET(x) ((x) & ~7)	/* State Offset */
#define  PCI_SRIOV_VFM_UA	0x0	/* Inactive.Unavailable */
#define  PCI_SRIOV_VFM_MI	0x1	/* Dormant.MigrateIn */
#define  PCI_SRIOV_VFM_MO	0x2	/* Active.MigrateOut */
#define  PCI_SRIOV_VFM_AV	0x3	/* Active.Available */
#define PCI_EXT_CAP_SRIOV_SIZEOF 64

#define PCI_LTR_MAX_SNOOP_LAT	0x4
#define PCI_LTR_MAX_NOSNOOP_LAT	0x6
#define  PCI_LTR_VALUE_MASK	0x000003ff
#define  PCI_LTR_SCALE_MASK	0x00001c00
#define  PCI_LTR_SCALE_SHIFT	10
#define PCI_EXT_CAP_LTR_SIZEOF	8

/* Access Control Service */
#define PCI_ACS_CAP		0x04	/* ACS Capability Register */
#define  PCI_ACS_SV		0x01	/* Source Validation */
#define  PCI_ACS_TB		0x02	/* Translation Blocking */
#define  PCI_ACS_RR		0x04	/* P2P Request Redirect */
#define  PCI_ACS_CR		0x08	/* P2P Completion Redirect */
#define  PCI_ACS_UF		0x10	/* Upstream Forwarding */
#define  PCI_ACS_EC		0x20	/* P2P Egress Control */
#define  PCI_ACS_DT		0x40	/* Direct Translated P2P */
#define PCI_ACS_EGRESS_BITS	0x05	/* ACS Egress Control Vector Size */
#define PCI_ACS_CTRL		0x06	/* ACS Control Register */
#define PCI_ACS_EGRESS_CTL_V	0x08	/* ACS Egress Control Vector */

#define PCI_VSEC_HDR		4	/* extended cap - vendor specific */
#define  PCI_VSEC_HDR_LEN_SHIFT	20	/* shift for length field */

/* sata capability */
#define PCI_SATA_REGS		4	/* SATA REGs specifier */
#define  PCI_SATA_REGS_MASK	0xF	/* location - BAR#/inline */
#define  PCI_SATA_REGS_INLINE	0xF	/* REGS in config space */
#define PCI_SATA_SIZEOF_SHORT	8
#define PCI_SATA_SIZEOF_LONG	16

/* resizable BARs */
#define PCI_REBAR_CTRL		8	/* control register */
#define  PCI_REBAR_CTRL_NBAR_MASK	(7 << 5)	/* mask for # bars */
#define  PCI_REBAR_CTRL_NBAR_SHIFT	5	/* shift for # bars */

/* dynamic power allocation */
#define PCI_DPA_CAP		4	/* capability register */
#define  PCI_DPA_CAP_SUBSTATE_MASK	0x1F	/* # substates - 1 */
#define PCI_DPA_BASE_SIZEOF	16	/* size with 0 substates */

/* TPH Requester */
#define PCI_TPH_CAP		4	/* capability register */
#define  PCI_TPH_CAP_LOC_MASK	0x600	/* location mask */
#define   PCI_TPH_LOC_NONE	0x000	/* no location */
#define   PCI_TPH_LOC_CAP	0x200	/* in capability */
#define   PCI_TPH_LOC_MSIX	0x400	/* in MSI-X */
#define PCI_TPH_CAP_ST_MASK	0x07FF0000	/* st table mask */
#define PCI_TPH_CAP_ST_SHIFT	16	/* st table shift */
#define PCI_TPH_BASE_SIZEOF	12	/* size with no st table */
















/*
 * Device identification register; contains a vendor ID and a device ID.
 */
#define	PCI_ID_REG			0x00

typedef u16 pci_vendor_id_t;
typedef u16 pci_product_id_t;

#define	PCI_VENDOR_SHIFT			0
#define	PCI_VENDOR_MASK				0xffff
#define	PCI_VENDOR(id) \
	    (((id) >> PCI_VENDOR_SHIFT) & PCI_VENDOR_MASK)

#define	PCI_PRODUCT_SHIFT			16
#define	PCI_PRODUCT_MASK			0xffff
#define	PCI_PRODUCT(id) \
	    (((id) >> PCI_PRODUCT_SHIFT) & PCI_PRODUCT_MASK)

#define PCI_ID_CODE(vid,pid)					\
	((((vid) & PCI_VENDOR_MASK) << PCI_VENDOR_SHIFT) |	\
	 (((pid) & PCI_PRODUCT_MASK) << PCI_PRODUCT_SHIFT))	\

/*
 * Command and status register.
 */
#define	PCI_COMMAND_STATUS_REG			0x04
#define	PCI_COMMAND_SHIFT			0
#define	PCI_COMMAND_MASK			0xffff
#define	PCI_STATUS_SHIFT			16
#define	PCI_STATUS_MASK				0xffff

#define PCI_COMMAND_STATUS_CODE(cmd,stat)			\
	((((cmd) & PCI_COMMAND_MASK) >> PCI_COMMAND_SHIFT) |	\
	 (((stat) & PCI_STATUS_MASK) >> PCI_STATUS_SHIFT))	\

#define	PCI_COMMAND_IO_ENABLE			0x00000001
#define	PCI_COMMAND_MEM_ENABLE			0x00000002
#define	PCI_COMMAND_MASTER_ENABLE		0x00000004
#define	PCI_COMMAND_SPECIAL_ENABLE		0x00000008
#define	PCI_COMMAND_INVALIDATE_ENABLE		0x00000010
#define	PCI_COMMAND_PALETTE_ENABLE		0x00000020
#define	PCI_COMMAND_PARITY_ENABLE		0x00000040
#define	PCI_COMMAND_STEPPING_ENABLE		0x00000080
#define	PCI_COMMAND_SERR_ENABLE			0x00000100
#define	PCI_COMMAND_BACKTOBACK_ENABLE		0x00000200
#define PCI_COMMAND_INTX_DISABLE		0x400 /* INTx Emulation Disable */

/*
 * PCI Class and Revision Register; defines type and revision of device.
 */
#define	PCI_CLASS_REG			0x08

typedef u8 pci_class_t;
typedef u8 pci_subclass_t;
typedef u8 pci_interface_t;
typedef u8 pci_revision_t;

#define	PCI_CLASS_SHIFT				24
#define	PCI_CLASS_MASK				0xff
#define	PCI_CLASS(cr) \
	    (((cr) >> PCI_CLASS_SHIFT) & PCI_CLASS_MASK)

#define	PCI_SUBCLASS_SHIFT			16
#define	PCI_SUBCLASS_MASK			0xff
#define	PCI_SUBCLASS(cr) \
	    (((cr) >> PCI_SUBCLASS_SHIFT) & PCI_SUBCLASS_MASK)

#define	PCI_INTERFACE_SHIFT			8
#define	PCI_INTERFACE_MASK			0xff
#define	PCI_INTERFACE(cr) \
	    (((cr) >> PCI_INTERFACE_SHIFT) & PCI_INTERFACE_MASK)

#define	PCI_REVISION_SHIFT			0
#define	PCI_REVISION_MASK			0xff
#define	PCI_REVISION(cr) \
	    (((cr) >> PCI_REVISION_SHIFT) & PCI_REVISION_MASK)

#define	PCI_CLASS_CODE(mainclass, subclass, interface) \
	    ((((mainclass) & PCI_CLASS_MASK) << PCI_CLASS_SHIFT) | \
	     (((subclass) & PCI_SUBCLASS_MASK) << PCI_SUBCLASS_SHIFT) | \
	     (((interface) & PCI_INTERFACE_MASK) << PCI_INTERFACE_SHIFT))

/* base classes */
#define	PCI_CLASS_PREHISTORIC			0x00
#define	PCI_CLASS_MASS_STORAGE			0x01
#define	PCI_CLASS_NETWORK			0x02
#define	PCI_CLASS_DISPLAY			0x03
#define	PCI_CLASS_MULTIMEDIA			0x04
#define	PCI_CLASS_MEMORY			0x05
#define	PCI_CLASS_BRIDGE			0x06
#define	PCI_CLASS_COMMUNICATIONS		0x07
#define	PCI_CLASS_SYSTEM			0x08
#define	PCI_CLASS_INPUT				0x09
#define	PCI_CLASS_DOCK				0x0a
#define	PCI_CLASS_PROCESSOR			0x0b
#define	PCI_CLASS_SERIALBUS			0x0c
#define	PCI_CLASS_WIRELESS			0x0d
#define	PCI_CLASS_I2O				0x0e
#define	PCI_CLASS_SATCOM			0x0f
#define	PCI_CLASS_CRYPTO			0x10
#define	PCI_CLASS_DASP				0x11
#define	PCI_CLASS_UNDEFINED			0xff

/* 0x00 prehistoric subclasses */
#define	PCI_SUBCLASS_PREHISTORIC_MISC		0x00
#define	PCI_SUBCLASS_PREHISTORIC_VGA		0x01

/* 0x01 mass storage subclasses */
#define	PCI_SUBCLASS_MASS_STORAGE_SCSI		0x00
#define	PCI_SUBCLASS_MASS_STORAGE_IDE		0x01
#define	PCI_SUBCLASS_MASS_STORAGE_FLOPPY	0x02
#define	PCI_SUBCLASS_MASS_STORAGE_IPI		0x03
#define	PCI_SUBCLASS_MASS_STORAGE_RAID		0x04
#define	PCI_SUBCLASS_MASS_STORAGE_ATA		0x05
#define	PCI_SUBCLASS_MASS_STORAGE_SATA		0x06
#define	PCI_SUBCLASS_MASS_STORAGE_MISC		0x80

/* 0x02 network subclasses */
#define	PCI_SUBCLASS_NETWORK_ETHERNET		0x00
#define	PCI_SUBCLASS_NETWORK_TOKENRING		0x01
#define	PCI_SUBCLASS_NETWORK_FDDI		0x02
#define	PCI_SUBCLASS_NETWORK_ATM		0x03
#define	PCI_SUBCLASS_NETWORK_ISDN		0x04
#define	PCI_SUBCLASS_NETWORK_WORLDFIP		0x05
#define	PCI_SUBCLASS_NETWORK_PCIMGMULTICOMP	0x06
#define	PCI_SUBCLASS_NETWORK_MISC		0x80

/* 0x03 display subclasses */
#define	PCI_SUBCLASS_DISPLAY_VGA		0x00
#define	PCI_SUBCLASS_DISPLAY_XGA		0x01
#define	PCI_SUBCLASS_DISPLAY_3D			0x02
#define	PCI_SUBCLASS_DISPLAY_MISC		0x80

/* 0x04 multimedia subclasses */
#define	PCI_SUBCLASS_MULTIMEDIA_VIDEO		0x00
#define	PCI_SUBCLASS_MULTIMEDIA_AUDIO		0x01
#define	PCI_SUBCLASS_MULTIMEDIA_TELEPHONY	0x02
#define	PCI_SUBCLASS_MULTIMEDIA_MISC		0x80

/* 0x05 memory subclasses */
#define	PCI_SUBCLASS_MEMORY_RAM			0x00
#define	PCI_SUBCLASS_MEMORY_FLASH		0x01
#define	PCI_SUBCLASS_MEMORY_MISC		0x80

/* 0x06 bridge subclasses */
#define	PCI_SUBCLASS_BRIDGE_HOST		0x00
#define	PCI_SUBCLASS_BRIDGE_ISA			0x01
#define	PCI_SUBCLASS_BRIDGE_EISA		0x02
#define	PCI_SUBCLASS_BRIDGE_MC			0x03	/* XXX _MCA? */
#define	PCI_SUBCLASS_BRIDGE_PCI			0x04
#define	PCI_SUBCLASS_BRIDGE_PCMCIA		0x05
#define	PCI_SUBCLASS_BRIDGE_NUBUS		0x06
#define	PCI_SUBCLASS_BRIDGE_CARDBUS		0x07
#define	PCI_SUBCLASS_BRIDGE_RACEWAY		0x08
#define	PCI_SUBCLASS_BRIDGE_STPCI		0x09
#define	PCI_SUBCLASS_BRIDGE_INFINIBAND		0x0a
#define	PCI_SUBCLASS_BRIDGE_MISC		0x80

/* 0x07 communications subclasses */
#define	PCI_SUBCLASS_COMMUNICATIONS_SERIAL	0x00
#define	PCI_SUBCLASS_COMMUNICATIONS_PARALLEL	0x01
#define	PCI_SUBCLASS_COMMUNICATIONS_MPSERIAL	0x02
#define	PCI_SUBCLASS_COMMUNICATIONS_MODEM	0x03
#define	PCI_SUBCLASS_COMMUNICATIONS_GPIB	0x04
#define	PCI_SUBCLASS_COMMUNICATIONS_SMARTCARD	0x05
#define	PCI_SUBCLASS_COMMUNICATIONS_MISC	0x80

/* 0x08 system subclasses */
#define	PCI_SUBCLASS_SYSTEM_PIC			0x00
#define	PCI_SUBCLASS_SYSTEM_DMA			0x01
#define	PCI_SUBCLASS_SYSTEM_TIMER		0x02
#define	PCI_SUBCLASS_SYSTEM_RTC			0x03
#define	PCI_SUBCLASS_SYSTEM_PCIHOTPLUG		0x04
#define	PCI_SUBCLASS_SYSTEM_MISC		0x80

/* 0x09 input subclasses */
#define	PCI_SUBCLASS_INPUT_KEYBOARD		0x00
#define	PCI_SUBCLASS_INPUT_DIGITIZER		0x01
#define	PCI_SUBCLASS_INPUT_MOUSE		0x02
#define	PCI_SUBCLASS_INPUT_SCANNER		0x03
#define	PCI_SUBCLASS_INPUT_GAMEPORT		0x04
#define	PCI_SUBCLASS_INPUT_MISC			0x80

/* 0x0a dock subclasses */
#define	PCI_SUBCLASS_DOCK_GENERIC		0x00
#define	PCI_SUBCLASS_DOCK_MISC			0x80

/* 0x0b processor subclasses */
#define	PCI_SUBCLASS_PROCESSOR_386		0x00
#define	PCI_SUBCLASS_PROCESSOR_486		0x01
#define	PCI_SUBCLASS_PROCESSOR_PENTIUM		0x02
#define	PCI_SUBCLASS_PROCESSOR_ALPHA		0x10
#define	PCI_SUBCLASS_PROCESSOR_POWERPC		0x20
#define	PCI_SUBCLASS_PROCESSOR_MIPS		0x30
#define	PCI_SUBCLASS_PROCESSOR_COPROC		0x40

/* 0x0c serial bus subclasses */
#define	PCI_SUBCLASS_SERIALBUS_FIREWIRE		0x00
#define	PCI_SUBCLASS_SERIALBUS_ACCESS		0x01
#define	PCI_SUBCLASS_SERIALBUS_SSA		0x02
#define	PCI_SUBCLASS_SERIALBUS_USB		0x03
#define	PCI_SUBCLASS_SERIALBUS_FIBER		0x04	/* XXX _FIBRECHANNEL */
#define	PCI_SUBCLASS_SERIALBUS_SMBUS		0x05
#define	PCI_SUBCLASS_SERIALBUS_INFINIBAND	0x06
#define	PCI_SUBCLASS_SERIALBUS_IPMI		0x07
#define	PCI_SUBCLASS_SERIALBUS_SERCOS		0x08
#define	PCI_SUBCLASS_SERIALBUS_CANBUS		0x09

/* 0x0d wireless subclasses */
#define	PCI_SUBCLASS_WIRELESS_IRDA		0x00
#define	PCI_SUBCLASS_WIRELESS_CONSUMERIR	0x01
#define	PCI_SUBCLASS_WIRELESS_RF		0x10
#define	PCI_SUBCLASS_WIRELESS_BLUETOOTH		0x11
#define	PCI_SUBCLASS_WIRELESS_BROADBAND		0x12
#define	PCI_SUBCLASS_WIRELESS_802_11A		0x20
#define	PCI_SUBCLASS_WIRELESS_802_11B		0x21
#define	PCI_SUBCLASS_WIRELESS_MISC		0x80

/* 0x0e I2O (Intelligent I/O) subclasses */
#define	PCI_SUBCLASS_I2O_STANDARD		0x00

/* 0x0f satellite communication subclasses */
/*	PCI_SUBCLASS_SATCOM_???			0x00	/ * XXX ??? */
#define	PCI_SUBCLASS_SATCOM_TV			0x01
#define	PCI_SUBCLASS_SATCOM_AUDIO		0x02
#define	PCI_SUBCLASS_SATCOM_VOICE		0x03
#define	PCI_SUBCLASS_SATCOM_DATA		0x04

/* 0x10 encryption/decryption subclasses */
#define	PCI_SUBCLASS_CRYPTO_NETCOMP		0x00
#define	PCI_SUBCLASS_CRYPTO_ENTERTAINMENT	0x10
#define	PCI_SUBCLASS_CRYPTO_MISC		0x80

/* 0x11 data acquisition and signal processing subclasses */
#define	PCI_SUBCLASS_DASP_DPIO			0x00
#define	PCI_SUBCLASS_DASP_TIMEFREQ		0x01
#define	PCI_SUBCLASS_DASP_SYNC			0x10
#define	PCI_SUBCLASS_DASP_MGMT			0x20
#define	PCI_SUBCLASS_DASP_MISC			0x80

/*
 * PCI BIST/Header Type/Latency Timer/Cache Line Size Register.
 */
#define	PCI_BHLC_REG			0x0c

#define	PCI_BIST_MASK				0xff

#define	PCI_HDRTYPE_SHIFT			16
#define	PCI_HDRTYPE_MASK			0xff
#define	PCI_HDRTYPE(bhlcr) \
	    (((bhlcr) >> PCI_HDRTYPE_SHIFT) & PCI_HDRTYPE_MASK)

#define	PCI_HDRTYPE_TYPE(bhlcr) \
	    (PCI_HDRTYPE(bhlcr) & 0x7f)
#define	PCI_HDRTYPE_MULTIFN(bhlcr) \
	    ((PCI_HDRTYPE(bhlcr) & 0x80) != 0)

#define	PCI_LATTIMER_SHIFT			8
#define	PCI_LATTIMER_MASK			0xff
#define	PCI_LATTIMER(bhlcr) \
	    (((bhlcr) >> PCI_LATTIMER_SHIFT) & PCI_LATTIMER_MASK)

#define	PCI_CACHELINE_SHIFT			0
#define	PCI_CACHELINE_MASK			0xff
#define	PCI_CACHELINE(bhlcr) \
	    (((bhlcr) >> PCI_CACHELINE_SHIFT) & PCI_CACHELINE_MASK)

#define PCI_BHLC_CODE(bist,type,multi,latency,cacheline)		\
	    ((((bist) & PCI_BIST_MASK) << PCI_BIST_SHIFT) |		\
	     (((type) & PCI_HDRTYPE_MASK) << PCI_HDRTYPE_SHIFT) |	\
	     (((multi)?0x80:0) << PCI_HDRTYPE_SHIFT) |			\
	     (((latency) & PCI_LATTIMER_MASK) << PCI_LATTIMER_SHIFT) |	\
	     (((cacheline) & PCI_CACHELINE_MASK) << PCI_CACHELINE_SHIFT))

/*
 * PCI header type
 */
#define PCI_HDRTYPE_DEVICE	0
#define PCI_HDRTYPE_PPB		1
#define PCI_HDRTYPE_PCB		2

/*
 * Mapping registers
 */
#define	PCI_MAPREG_START		0x10
#define	PCI_MAPREG_END			0x28
#define	PCI_MAPREG_ROM			0x30
#define	PCI_MAPREG_PPB_END		0x18
#define	PCI_MAPREG_PCB_END		0x14

#define	PCI_MAPREG_TYPE(mr)						\
	    ((mr) & PCI_MAPREG_TYPE_MASK)
#define	PCI_MAPREG_TYPE_MASK			0x00000001

#define	PCI_MAPREG_TYPE_MEM			0x00000000
#define	PCI_MAPREG_TYPE_IO			0x00000001
#define	PCI_MAPREG_ROM_ENABLE			0x00000001

#define	PCI_MAPREG_MEM_TYPE(mr)						\
	    ((mr) & PCI_MAPREG_MEM_TYPE_MASK)
#define	PCI_MAPREG_MEM_TYPE_MASK		0x00000006

#define	PCI_MAPREG_MEM_TYPE_32BIT		0x00000000
#define	PCI_MAPREG_MEM_TYPE_32BIT_1M		0x00000002
#define	PCI_MAPREG_MEM_TYPE_64BIT		0x00000004

#define	PCI_MAPREG_MEM_PREFETCHABLE(mr)				\
	    (((mr) & PCI_MAPREG_MEM_PREFETCHABLE_MASK) != 0)
#define	PCI_MAPREG_MEM_PREFETCHABLE_MASK	0x00000008

#define	PCI_MAPREG_MEM_ADDR(mr)						\
	    ((mr) & PCI_MAPREG_MEM_ADDR_MASK)
#define	PCI_MAPREG_MEM_SIZE(mr)						\
	    (PCI_MAPREG_MEM_ADDR(mr) & -PCI_MAPREG_MEM_ADDR(mr))
#define	PCI_MAPREG_MEM_ADDR_MASK		0xfffffff0

#define	PCI_MAPREG_MEM64_ADDR(mr)					\
	    ((mr) & PCI_MAPREG_MEM64_ADDR_MASK)
#define	PCI_MAPREG_MEM64_SIZE(mr)					\
	    (PCI_MAPREG_MEM64_ADDR(mr) & -PCI_MAPREG_MEM64_ADDR(mr))
#define	PCI_MAPREG_MEM64_ADDR_MASK		0xfffffffffffffff0ULL

#define	PCI_MAPREG_IO_ADDR(mr)						\
	    ((mr) & PCI_MAPREG_IO_ADDR_MASK)
#define	PCI_MAPREG_IO_SIZE(mr)						\
	    (PCI_MAPREG_IO_ADDR(mr) & -PCI_MAPREG_IO_ADDR(mr))
#define	PCI_MAPREG_IO_ADDR_MASK			0xfffffffc

#define PCI_MAPREG_SIZE_TO_MASK(size)					\
	    (-(size))

#define PCI_MAPREG_NUM(offset)						\
	    (((unsigned)(offset)-PCI_MAPREG_START)/4)


/*
 * Cardbus CIS pointer (PCI rev. 2.1)
 */
#define PCI_CARDBUS_CIS_REG 0x28

/*
 * Subsystem identification register; contains a vendor ID and a device ID.
 * Types/macros for PCI_ID_REG apply.
 * (PCI rev. 2.1)
 */
#define PCI_SUBSYS_ID_REG 0x2c

/*
 * Capabilities link list (PCI rev. 2.2)
 */
#define	PCI_CAPLISTPTR_REG		0x34	/* header type 0 */
#define	PCI_CARDBUS_CAPLISTPTR_REG	0x14	/* header type 2 */
#define	PCI_CAPLIST_PTR(cpr)	((cpr) & 0xff)
#define	PCI_CAPLIST_NEXT(cr)	(((cr) >> 8) & 0xff)
#define	PCI_CAPLIST_CAP(cr)	((cr) & 0xff)

#define	PCI_CAP_RESERVED0	0x00
#define	PCI_CAP_PWRMGMT		0x01
#define	PCI_CAP_AGP		0x02
#define PCI_CAP_AGP_MAJOR(cr)	(((cr) >> 20) & 0xf)
#define PCI_CAP_AGP_MINOR(cr)	(((cr) >> 16) & 0xf)
#define	PCI_CAP_VPD		0x03
#define	PCI_CAP_SLOTID		0x04
#define	PCI_CAP_MSI		0x05
#define	PCI_CAP_CPCI_HOTSWAP	0x06
#define	PCI_CAP_PCIX		0x07
#define	PCI_CAP_LDT		0x08
#define	PCI_CAP_VENDSPEC	0x09
#define	PCI_CAP_DEBUGPORT	0x0a
#define	PCI_CAP_CPCI_RSRCCTL	0x0b
#define	PCI_CAP_HOTPLUG		0x0c
#define	PCI_CAP_AGP8		0x0e
#define	PCI_CAP_SECURE		0x0f
#define	PCI_CAP_PCIEXPRESS     	0x10
#define	PCI_CAP_MSIX		0x11

/*
 * Vital Product Data; access via capability pointer (PCI rev 2.2).
 */
#define	PCI_VPD_ADDRESS_MASK	0x7fff
#define	PCI_VPD_ADDRESS_SHIFT	16
#define	PCI_VPD_ADDRESS(ofs)	\
	(((ofs) & PCI_VPD_ADDRESS_MASK) << PCI_VPD_ADDRESS_SHIFT)
#define	PCI_VPD_DATAREG(ofs)	((ofs) + 4)
#define	PCI_VPD_OPFLAG		0x80000000

/*
 * Power Management Capability; access via capability pointer.
 */

/* Power Management Capability Register */
#define PCI_PMCR		0x02
#define PCI_PMCR_D1SUPP		0x0200
#define PCI_PMCR_D2SUPP		0x0400
/* Power Management Control Status Register */
#define PCI_PMCSR		0x04
#define PCI_PMCSR_STATE_MASK	0x03
#define PCI_PMCSR_STATE_D0      0x00
#define PCI_PMCSR_STATE_D1      0x01
#define PCI_PMCSR_STATE_D2      0x02
#define PCI_PMCSR_STATE_D3      0x03

/*
 * PCI-X capability.
 */

/*
 * Command. 16 bits at offset 2 (e.g. upper 16 bits of the first 32-bit
 * word at the capability; the lower 16 bits are the capability ID and
 * next capability pointer).
 *
 * Since we always read PCI config space in 32-bit words, we define these
 * as 32-bit values, offset and shifted appropriately.  Make sure you perform
 * the appropriate R/M/W cycles!
 */
#define PCI_PCIX_CMD			0x00
#define PCI_PCIX_CMD_PERR_RECOVER	0x00010000
#define PCI_PCIX_CMD_RELAXED_ORDER	0x00020000
#define PCI_PCIX_CMD_BYTECNT_MASK	0x000c0000
#define	PCI_PCIX_CMD_BYTECNT_SHIFT	18
#define		PCI_PCIX_CMD_BCNT_512		0x00000000
#define		PCI_PCIX_CMD_BCNT_1024		0x00040000
#define		PCI_PCIX_CMD_BCNT_2048		0x00080000
#define		PCI_PCIX_CMD_BCNT_4096		0x000c0000
#define PCI_PCIX_CMD_SPLTRANS_MASK	0x00700000
#define		PCI_PCIX_CMD_SPLTRANS_1		0x00000000
#define		PCI_PCIX_CMD_SPLTRANS_2		0x00100000
#define		PCI_PCIX_CMD_SPLTRANS_3		0x00200000
#define		PCI_PCIX_CMD_SPLTRANS_4		0x00300000
#define		PCI_PCIX_CMD_SPLTRANS_8		0x00400000
#define		PCI_PCIX_CMD_SPLTRANS_12	0x00500000
#define		PCI_PCIX_CMD_SPLTRANS_16	0x00600000
#define		PCI_PCIX_CMD_SPLTRANS_32	0x00700000

/*
 * Status. 32 bits at offset 4.
 */
#define PCI_PCIX_STATUS			0x04
#define PCI_PCIX_STATUS_FN_MASK		0x00000007
#define PCI_PCIX_STATUS_DEV_MASK	0x000000f8
#define PCI_PCIX_STATUS_BUS_MASK	0x0000ff00
#define PCI_PCIX_STATUS_64BIT		0x00010000
#define PCI_PCIX_STATUS_133		0x00020000
#define PCI_PCIX_STATUS_SPLDISC		0x00040000
#define PCI_PCIX_STATUS_SPLUNEX		0x00080000
#define PCI_PCIX_STATUS_DEVCPLX		0x00100000
#define PCI_PCIX_STATUS_MAXB_MASK	0x00600000
#define	PCI_PCIX_STATUS_MAXB_SHIFT	21
#define		PCI_PCIX_STATUS_MAXB_512	0x00000000
#define		PCI_PCIX_STATUS_MAXB_1024	0x00200000
#define		PCI_PCIX_STATUS_MAXB_2048	0x00400000
#define		PCI_PCIX_STATUS_MAXB_4096	0x00600000
#define PCI_PCIX_STATUS_MAXST_MASK	0x03800000
#define		PCI_PCIX_STATUS_MAXST_1		0x00000000
#define		PCI_PCIX_STATUS_MAXST_2		0x00800000
#define		PCI_PCIX_STATUS_MAXST_3		0x01000000
#define		PCI_PCIX_STATUS_MAXST_4		0x01800000
#define		PCI_PCIX_STATUS_MAXST_8		0x02000000
#define		PCI_PCIX_STATUS_MAXST_12	0x02800000
#define		PCI_PCIX_STATUS_MAXST_16	0x03000000
#define		PCI_PCIX_STATUS_MAXST_32	0x03800000
#define PCI_PCIX_STATUS_MAXRS_MASK	0x1c000000
#define		PCI_PCIX_STATUS_MAXRS_1K	0x00000000
#define		PCI_PCIX_STATUS_MAXRS_2K	0x04000000
#define		PCI_PCIX_STATUS_MAXRS_4K	0x08000000
#define		PCI_PCIX_STATUS_MAXRS_8K	0x0c000000
#define		PCI_PCIX_STATUS_MAXRS_16K	0x10000000
#define		PCI_PCIX_STATUS_MAXRS_32K	0x14000000
#define		PCI_PCIX_STATUS_MAXRS_64K	0x18000000
#define		PCI_PCIX_STATUS_MAXRS_128K	0x1c000000
#define PCI_PCIX_STATUS_SCERR			0x20000000


/*
 * Interrupt Configuration Register; contains interrupt pin and line.
 */
#define	PCI_INTERRUPT_REG		0x3c

typedef u8 pci_intr_latency_t;
typedef u8 pci_intr_grant_t;
typedef u8 pci_intr_pin_t;
typedef u8 pci_intr_line_t;

#define	PCI_INTERRUPT_GRANT_SHIFT		24
#define	PCI_INTERRUPT_GRANT_MASK		0xff
#define	PCI_INTERRUPT_GRANT(icr) \
	    (((icr) >> PCI_INTERRUPT_GRANT_SHIFT) & PCI_INTERRUPT_GRANT_MASK)

#define	PCI_INTERRUPT_LATENCY_SHIFT		16
#define	PCI_INTERRUPT_LATENCY_MASK		0xff
#define	PCI_INTERRUPT_LATENCY(icr) \
	    (((icr) >> PCI_INTERRUPT_LATENCY_SHIFT) & PCI_INTERRUPT_LATENCY_MASK)

#define	PCI_INTERRUPT_PIN_SHIFT			8
#define	PCI_INTERRUPT_PIN_MASK			0xff

#define PCI_INTERRUPT_CODE(lat,gnt,pin,line)		\
	  ((((lat)&PCI_INTERRUPT_LATENCY_MASK)<<PCI_INTERRUPT_LATENCY_SHIFT)| \
	   (((gnt)&PCI_INTERRUPT_GRANT_MASK)  <<PCI_INTERRUPT_GRANT_SHIFT)  | \
	   (((pin)&PCI_INTERRUPT_PIN_MASK)    <<PCI_INTERRUPT_PIN_SHIFT)    | \
	   (((line)&PCI_INTERRUPT_LINE_MASK)  <<PCI_INTERRUPT_LINE_SHIFT))

#define	PCI_INTERRUPT_PIN_NONE			0x00
#define	PCI_INTERRUPT_PIN_A			0x01
#define	PCI_INTERRUPT_PIN_B			0x02
#define	PCI_INTERRUPT_PIN_C			0x03
#define	PCI_INTERRUPT_PIN_D			0x04
#define	PCI_INTERRUPT_PIN_MAX			0x04

/* Header Type 1 (Bridge) configuration registers */
#define PCI_BRIDGE_BUS_REG		0x18
#define   PCI_BRIDGE_BUS_PRIMARY_SHIFT		0
#define   PCI_BRIDGE_BUS_SECONDARY_SHIFT	8
#define   PCI_BRIDGE_BUS_SUBORDINATE_SHIFT	16

#define PCI_BRIDGE_STATIO_REG		0x1C
#define	  PCI_BRIDGE_STATIO_IOBASE_SHIFT	0
#define	  PCI_BRIDGE_STATIO_IOLIMIT_SHIFT	8
#define	  PCI_BRIDGE_STATIO_STATUS_SHIFT	16
#define	  PCI_BRIDGE_STATIO_IOBASE_MASK		0xf0
#define	  PCI_BRIDGE_STATIO_IOLIMIT_MASK	0xf0
#define	  PCI_BRIDGE_STATIO_STATUS_MASK		0xffff
#define	  PCI_BRIDGE_IO_32BITS(reg)		(((reg) & 0xf) == 1)

#define PCI_BRIDGE_MEMORY_REG		0x20
#define	  PCI_BRIDGE_MEMORY_BASE_SHIFT		4
#define	  PCI_BRIDGE_MEMORY_LIMIT_SHIFT		20
#define	  PCI_BRIDGE_MEMORY_BASE_MASK		0xffff
#define	  PCI_BRIDGE_MEMORY_LIMIT_MASK		0xffff

#define PCI_BRIDGE_PREFETCHMEM_REG	0x24
#define	  PCI_BRIDGE_PREFETCHMEM_BASE_SHIFT	4
#define	  PCI_BRIDGE_PREFETCHMEM_LIMIT_SHIFT	20
#define	  PCI_BRIDGE_PREFETCHMEM_BASE_MASK	0xffff
#define	  PCI_BRIDGE_PREFETCHMEM_LIMIT_MASK	0xffff
#define	  PCI_BRIDGE_PREFETCHMEM_64BITS(reg)	((reg) & 0xf)

#define PCI_BRIDGE_PREFETCHBASE32_REG	0x28
#define PCI_BRIDGE_PREFETCHLIMIT32_REG	0x2C

#define PCI_BRIDGE_IOHIGH_REG		0x30
#define	  PCI_BRIDGE_IOHIGH_BASE_SHIFT		0
#define	  PCI_BRIDGE_IOHIGH_LIMIT_SHIFT		16
#define	  PCI_BRIDGE_IOHIGH_BASE_MASK		0xffff
#define	  PCI_BRIDGE_IOHIGH_LIMIT_MASK		0xffff

#define PCI_BRIDGE_CONTROL_REG		0x3C
#define	  PCI_BRIDGE_CONTROL_SHIFT		16
#define	  PCI_BRIDGE_CONTROL_MASK		0xffff
#define   PCI_BRIDGE_CONTROL_PERE		(1 <<  0)
#define   PCI_BRIDGE_CONTROL_SERR		(1 <<  1)
#define   PCI_BRIDGE_CONTROL_ISA		(1 <<  2)
#define   PCI_BRIDGE_CONTROL_VGA		(1 <<  3)
/* Reserved					(1 <<  4) */
#define   PCI_BRIDGE_CONTROL_MABRT		(1 <<  5)
#define   PCI_BRIDGE_CONTROL_SECBR		(1 <<  6)
#define   PCI_BRIDGE_CONTROL_SECFASTB2B		(1 <<  7)
#define   PCI_BRIDGE_CONTROL_PRI_DISC_TIMER	(1 <<  8)
#define   PCI_BRIDGE_CONTROL_SEC_DISC_TIMER	(1 <<  9)
#define   PCI_BRIDGE_CONTROL_DISC_TIMER_STAT	(1 << 10)
#define   PCI_BRIDGE_CONTROL_DISC_TIMER_SERR	(1 << 11)
/* Reserved					(1 << 12) - (1 << 15) */

/*
 * Vital Product Data resource tags.
 */
struct pci_vpd_smallres {
	u8		vpdres_byte0;		/* length of data + tag */
	/* Actual data. */
} __attribute__((__packed__));

struct pci_vpd_largeres {
	u8		vpdres_byte0;
	u8		vpdres_len_lsb;		/* length of data only */
	u8		vpdres_len_msb;
	/* Actual data. */
} __attribute__((__packed__));

#define	PCI_VPDRES_ISLARGE(x)			((x) & 0x80)

#define	PCI_VPDRES_SMALL_LENGTH(x)		((x) & 0x7)
#define	PCI_VPDRES_SMALL_NAME(x)		(((x) >> 3) & 0xf)

#define	PCI_VPDRES_LARGE_NAME(x)		((x) & 0x7f)

#define	PCI_VPDRES_TYPE_COMPATIBLE_DEVICE_ID	0x3	/* small */
#define	PCI_VPDRES_TYPE_VENDOR_DEFINED		0xe	/* small */
#define	PCI_VPDRES_TYPE_END_TAG			0xf	/* small */

#define	PCI_VPDRES_TYPE_IDENTIFIER_STRING	0x02	/* large */
#define	PCI_VPDRES_TYPE_VPD			0x10	/* large */

struct pci_vpd {
	u8		vpd_key0;
	u8		vpd_key1;
	u8		vpd_len;		/* length of data only */
	/* Actual data. */
} __attribute__((__packed__));

/*
 * Threshold below which 32bit PCI DMA needs bouncing.
 */
#define PCI32_DMA_BOUNCE_THRESHOLD	0x100000000ULL

#endif /* LEGO_PCI_REGS_H */
