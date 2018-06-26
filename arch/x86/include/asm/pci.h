/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_PCI_H_
#define _ASM_X86_PCI_H_

#include <lego/types.h>

/* Direct PCI access. This is used for PCI accesses in early boot before
   the PCI subsystem works. */

extern u32 read_pci_config(u8 bus, u8 slot, u8 func, u8 offset);
extern u8 read_pci_config_byte(u8 bus, u8 slot, u8 func, u8 offset);
extern u16 read_pci_config_16(u8 bus, u8 slot, u8 func, u8 offset);
extern void write_pci_config(u8 bus, u8 slot, u8 func, u8 offset, u32 val);
extern void write_pci_config_byte(u8 bus, u8 slot, u8 func, u8 offset, u8 val);
extern void write_pci_config_16(u8 bus, u8 slot, u8 func, u8 offset, u16 val);

extern int early_pci_allowed(void);

extern unsigned int pci_early_dump_regs;
extern void early_dump_pci_device(u8 bus, u8 slot, u8 func);
extern void early_dump_pci_devices(void);

#define PCI_PROBE_BIOS		0x0001
#define PCI_PROBE_CONF1		0x0002
#define PCI_PROBE_CONF2		0x0004
#define PCI_PROBE_MMCONF	0x0008
#define PCI_PROBE_MASK		0x000f
#define PCI_PROBE_NOEARLY	0x0010

#define PCI_NO_CHECKS		0x0400
#define PCI_USE_PIRQ_MASK	0x0800
#define PCI_ASSIGN_ROMS		0x1000
#define PCI_BIOS_IRQ_SCAN	0x2000
#define PCI_ASSIGN_ALL_BUSSES	0x4000
#define PCI_CAN_SKIP_ISA_ALIGN	0x8000
#define PCI_USE__CRS		0x10000
#define PCI_CHECK_ENABLE_AMD_MMCONF	0x20000
#define PCI_HAS_IO_ECS		0x40000
#define PCI_NOASSIGN_ROMS	0x80000
#define PCI_ROOT_NO_CRS		0x100000
#define PCI_NOASSIGN_BARS	0x200000

extern unsigned int pci_probe;

struct irq_info {
	u8 bus, devfn;			/* Bus, device and function */
	struct {
		u8 link;		/* IRQ line ID, chipset dependent,
					   0 = not routed */
		u16 bitmap;		/* Available IRQs */
	} __attribute__((packed)) irq[4];
	u8 slot;			/* Slot number, 0=onboard */
	u8 rfu;
} __attribute__((packed));

struct irq_routing_table {
	u32 signature;			/* PIRQ_SIGNATURE should be here */
	u16 version;			/* PIRQ_VERSION */
	u16 size;			/* Table size in bytes */
	u8 rtr_bus, rtr_devfn;		/* Where the interrupt router lies */
	u16 exclusive_irqs;		/* IRQs devoted exclusively to
					   PCI usage */
	u16 rtr_vendor, rtr_device;	/* Vendor and device ID of
					   interrupt router */
	u32 miniport_data;		/* Crap */
	u8 rfu[11];
	u8 checksum;			/* Modulo 256 checksum must give 0 */
	struct irq_info slots[0];
} __attribute__((packed));

struct pci_raw_ops {
	int (*read)(unsigned int domain, unsigned int bus, unsigned int devfn,
						int reg, int len, u32 *val);
	int (*write)(unsigned int domain, unsigned int bus, unsigned int devfn,
						int reg, int len, u32 val);
};

extern const struct pci_raw_ops *raw_pci_ops;
extern const struct pci_raw_ops *raw_pci_ext_ops;

extern const struct pci_raw_ops pci_mmcfg;
extern const struct pci_raw_ops pci_direct_conf1;

int __init pci_direct_probe(void);
void __init pci_direct_init(int type);

#endif /* _ASM_X86_PCI_H_ */
