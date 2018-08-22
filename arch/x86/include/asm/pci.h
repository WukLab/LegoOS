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
#include <lego/resource.h>

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
//#define PCI_CAN_SKIP_ISA_ALIGN	0x8000
#define PCI_USE__CRS		0x10000
#define PCI_CHECK_ENABLE_AMD_MMCONF	0x20000
#define PCI_HAS_IO_ECS		0x40000
#define PCI_NOASSIGN_ROMS	0x80000
#define PCI_ROOT_NO_CRS		0x100000
#define PCI_NOASSIGN_BARS	0x200000

unsigned int pcibios_assign_all_busses(void);

extern unsigned int pci_probe;
extern int pcibios_last_bus;

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

/* "PCI MMCONFIG %04x [bus %02x-%02x]" */
#define PCI_MMCFG_RESOURCE_NAME_LEN (22 + 4 + 2 + 2)

struct pci_mmcfg_region {
	struct list_head list;
	struct resource res;
	u64 address;
	char __iomem *virt;
	u16 segment;
	u8 start_bus;
	u8 end_bus;
	char name[PCI_MMCFG_RESOURCE_NAME_LEN];
};

extern int __init pci_mmcfg_arch_init(void);
extern void __init pci_mmcfg_arch_free(void);
extern int pci_mmcfg_arch_map(struct pci_mmcfg_region *cfg);
extern void pci_mmcfg_arch_unmap(struct pci_mmcfg_region *cfg);
extern int pci_mmconfig_insert(struct device *dev, u16 seg, u8 start, u8 end,
			       phys_addr_t addr);
extern int pci_mmconfig_delete(u16 seg, u8 start, u8 end);
extern struct pci_mmcfg_region *pci_mmconfig_lookup(int segment, int bus);

extern struct list_head pci_mmcfg_list;

#define PCI_MMCFG_BUS_OFFSET(bus)      ((bus) << 20)

/*
 * AMD Fam10h CPUs are buggy, and cannot access MMIO config space
 * on their northbrige except through the * %eax register. As such, you MUST
 * NOT use normal IOMEM accesses, you need to only use the magic mmio-config
 * accessor functions.
 * In fact just use pci_config_*, nothing else please.
 */
static inline unsigned char mmio_config_readb(void __iomem *pos)
{
	u8 val;
	asm volatile("movb (%1),%%al" : "=a" (val) : "r" (pos));
	return val;
}

static inline unsigned short mmio_config_readw(void __iomem *pos)
{
	u16 val;
	asm volatile("movw (%1),%%ax" : "=a" (val) : "r" (pos));
	return val;
}

static inline unsigned int mmio_config_readl(void __iomem *pos)
{
	u32 val;
	asm volatile("movl (%1),%%eax" : "=a" (val) : "r" (pos));
	return val;
}

static inline void mmio_config_writeb(void __iomem *pos, u8 val)
{
	asm volatile("movb %%al,(%1)" : : "a" (val), "r" (pos) : "memory");
}

static inline void mmio_config_writew(void __iomem *pos, u16 val)
{
	asm volatile("movw %%ax,(%1)" : : "a" (val), "r" (pos) : "memory");
}

static inline void mmio_config_writel(void __iomem *pos, u32 val)
{
	asm volatile("movl %%eax,(%1)" : : "a" (val), "r" (pos) : "memory");
}

struct pci_sysdata {
	int		domain;		/* PCI domain */
	int		node;		/* NUMA node */
	void		*acpi;		/* ACPI-specific data */
#ifdef CONFIG_X86_64
	void		*iommu;		/* IOMMU private data */
#endif
};

struct pci_dev;
extern int (*pcibios_enable_irq)(struct pci_dev *dev);
extern void (*pcibios_disable_irq)(struct pci_dev *dev);

#ifdef CONFIG_PCI_MSI
struct x86_msi_ops {
	int (*setup_msi_irqs)(struct pci_dev *dev, int nvec, int type);
	void (*compose_msi_msg)(struct pci_dev *dev, unsigned int irq,
				unsigned int dest, struct msi_msg *msg,
			       u8 hpet_id);
	void (*teardown_msi_irq)(unsigned int irq);
	void (*teardown_msi_irqs)(struct pci_dev *dev);
	void (*restore_msi_irqs)(struct pci_dev *dev, int irq);
	int  (*setup_hpet_msi)(unsigned int irq, unsigned int id);
};

extern struct x86_msi_ops x86_msi;

/* MSI arch specific hooks */
static inline int x86_setup_msi_irqs(struct pci_dev *dev, int nvec, int type)
{
	return x86_msi.setup_msi_irqs(dev, nvec, type);
}

static inline void x86_teardown_msi_irqs(struct pci_dev *dev)
{
	x86_msi.teardown_msi_irqs(dev);
}

static inline void x86_teardown_msi_irq(unsigned int irq)
{
	x86_msi.teardown_msi_irq(irq);
}
static inline void x86_restore_msi_irqs(struct pci_dev *dev, int irq)
{
	x86_msi.restore_msi_irqs(dev, irq);
}
#define arch_setup_msi_irqs x86_setup_msi_irqs
#define arch_teardown_msi_irqs x86_teardown_msi_irqs
#define arch_teardown_msi_irq x86_teardown_msi_irq
#define arch_restore_msi_irqs x86_restore_msi_irqs
/* implemented in arch/x86/kernel/apic/io_apic. */
struct msi_desc;
int native_setup_msi_irqs(struct pci_dev *dev, int nvec, int type);
void native_teardown_msi_irq(unsigned int irq);
void native_restore_msi_irqs(struct pci_dev *dev, int irq);
int setup_msi_irq(struct pci_dev *dev, struct msi_desc *msidesc,
		  unsigned int irq_base, unsigned int irq_offset);
/* default to the implementation in drivers/lib/msi.c */
#define HAVE_DEFAULT_MSI_TEARDOWN_IRQS
#define HAVE_DEFAULT_MSI_RESTORE_IRQS
void default_teardown_msi_irqs(struct pci_dev *dev);
void default_restore_msi_irqs(struct pci_dev *dev, int irq);
#else
#define native_setup_msi_irqs		NULL
#define native_teardown_msi_irq		NULL
#define default_teardown_msi_irqs	NULL
#define default_restore_msi_irqs	NULL
#endif

#endif /* _ASM_X86_PCI_H_ */
