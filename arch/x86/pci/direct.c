/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * Direct harware configuration space access mechanism type 1 and type 2.
 * Type 2 was deprecated since PCI 2.0, so normally we end up using type 1 to
 * access PCI configuration space. If you end up using type 2, here is a nickel,
 * go buy yourself a real computer.
 *
 *	- Yizhou
 */

#include <lego/pci.h>
#include <lego/kernel.h>
#include <lego/resource.h>
#include <asm/io.h>
#include <asm/pci.h>

/* Set if either type 1 or type 2 PCI is detected */
bool port_cf9_safe = false;

/*
 * This interrupt-safe spinlock protects all accesses to PCI
 * configuration space.
 */
DEFINE_SPINLOCK(pci_config_lock);

/*
 * Functions for accessing PCI base (first 256 bytes) and extended
 * (4096 bytes per PCI function) configuration space with type 1
 * accesses.
 */

#define PCI_CONF1_ADDRESS(bus, devfn, reg) \
	(0x80000000 | ((reg & 0xF00) << 16) | (bus << 16) \
	| (devfn << 8) | (reg & 0xFC))

static int pci_conf1_read(unsigned int seg, unsigned int bus,
			  unsigned int devfn, int reg, int len, u32 *value)
{
	unsigned long flags;

	if (seg || (bus > 255) || (devfn > 255) || (reg > 4095)) {
		*value = -1;
		return -EINVAL;
	}

	spin_lock_irqsave(&pci_config_lock, flags);

	outl(PCI_CONF1_ADDRESS(bus, devfn, reg), 0xCF8);

	switch (len) {
	case 1:
		*value = inb(0xCFC + (reg & 3));
		break;
	case 2:
		*value = inw(0xCFC + (reg & 2));
		break;
	case 4:
		*value = inl(0xCFC);
		break;
	}

	spin_unlock_irqrestore(&pci_config_lock, flags);

	return 0;
}

static int pci_conf1_write(unsigned int seg, unsigned int bus,
			   unsigned int devfn, int reg, int len, u32 value)
{
	unsigned long flags;

	if (seg || (bus > 255) || (devfn > 255) || (reg > 4095))
		return -EINVAL;

	spin_lock_irqsave(&pci_config_lock, flags);

	outl(PCI_CONF1_ADDRESS(bus, devfn, reg), 0xCF8);

	switch (len) {
	case 1:
		outb((u8)value, 0xCFC + (reg & 3));
		break;
	case 2:
		outw((u16)value, 0xCFC + (reg & 2));
		break;
	case 4:
		outl((u32)value, 0xCFC);
		break;
	}

	spin_unlock_irqrestore(&pci_config_lock, flags);

	return 0;
}

#undef PCI_CONF1_ADDRESS

const struct pci_raw_ops pci_direct_conf1 = {
	.read =		pci_conf1_read,
	.write =	pci_conf1_write,
};


/*
 * Functions for accessing PCI configuration space with type 2 accesses
 */

#define PCI_CONF2_ADDRESS(dev, reg)	(u16)(0xC000 | (dev << 8) | reg)

static int pci_conf2_read(unsigned int seg, unsigned int bus,
			  unsigned int devfn, int reg, int len, u32 *value)
{
	unsigned long flags;
	int dev, fn;

	WARN_ON(seg);
	if ((bus > 255) || (devfn > 255) || (reg > 255)) {
		*value = -1;
		return -EINVAL;
	}

	dev = PCI_SLOT(devfn);
	fn = PCI_FUNC(devfn);

	if (dev & 0x10)
		return PCIBIOS_DEVICE_NOT_FOUND;

	spin_lock_irqsave(&pci_config_lock, flags);

	outb((u8)(0xF0 | (fn << 1)), 0xCF8);
	outb((u8)bus, 0xCFA);

	switch (len) {
	case 1:
		*value = inb(PCI_CONF2_ADDRESS(dev, reg));
		break;
	case 2:
		*value = inw(PCI_CONF2_ADDRESS(dev, reg));
		break;
	case 4:
		*value = inl(PCI_CONF2_ADDRESS(dev, reg));
		break;
	}

	outb(0, 0xCF8);

	spin_unlock_irqrestore(&pci_config_lock, flags);

	return 0;
}

static int pci_conf2_write(unsigned int seg, unsigned int bus,
			   unsigned int devfn, int reg, int len, u32 value)
{
	unsigned long flags;
	int dev, fn;

	WARN_ON(seg);
	if ((bus > 255) || (devfn > 255) || (reg > 255))
		return -EINVAL;

	dev = PCI_SLOT(devfn);
	fn = PCI_FUNC(devfn);

	if (dev & 0x10)
		return PCIBIOS_DEVICE_NOT_FOUND;

	spin_lock_irqsave(&pci_config_lock, flags);

	outb((u8)(0xF0 | (fn << 1)), 0xCF8);
	outb((u8)bus, 0xCFA);

	switch (len) {
	case 1:
		outb((u8)value, PCI_CONF2_ADDRESS(dev, reg));
		break;
	case 2:
		outw((u16)value, PCI_CONF2_ADDRESS(dev, reg));
		break;
	case 4:
		outl((u32)value, PCI_CONF2_ADDRESS(dev, reg));
		break;
	}

	outb(0, 0xCF8);

	spin_unlock_irqrestore(&pci_config_lock, flags);

	return 0;
}

#undef PCI_CONF2_ADDRESS

static const struct pci_raw_ops pci_direct_conf2 = {
	.read =		pci_conf2_read,
	.write =	pci_conf2_write,
};

static int __init pci_check_type1(void)
{
	unsigned long flags;
	unsigned int tmp;
	int works = 0;

	local_irq_save(flags);

	outb(0x01, 0xCFB);
	tmp = inl(0xCF8);
	outl(0x80000000, 0xCF8);
	if (inl(0xCF8) == 0x80000000)
		works = 1;
	outl(tmp, 0xCF8);
	local_irq_restore(flags);

	return works;
}

static int __init pci_check_type2(void)
{
	unsigned long flags;
	int works = 0;

	local_irq_save(flags);

	outb(0x00, 0xCFB);
	outb(0x00, 0xCF8);
	outb(0x00, 0xCFA);
	if (inb(0xCF8) == 0x00 && inb(0xCFA) == 0x00)
		works = 1;

	local_irq_restore(flags);

	return works;
}

void __init pci_direct_init(int type)
{
	if (type == 0)
		return;

	pr_info("PCI: Using configuration type %d for base access\n", type);

	if (type == 1) {
		raw_pci_ops = &pci_direct_conf1;
		if (raw_pci_ext_ops)
			return;
		if (!(pci_probe & PCI_HAS_IO_ECS))
			return;
		printk(KERN_INFO "PCI: Using configuration type 1 "
		       "for extended access\n");
		raw_pci_ext_ops = &pci_direct_conf1;
		return;
	}
	raw_pci_ops = &pci_direct_conf2;
}

int __init pci_direct_probe(void)
{
	if ((pci_probe & PCI_PROBE_CONF1) == 0)
		goto type2;
	if (!request_region(0xCF8, 8, "PCI conf1"))
		goto type2;

	if (pci_check_type1()) {
		raw_pci_ops = &pci_direct_conf1;
		port_cf9_safe = true;
		return 1;
	}
	release_region(0xCF8, 8);

type2:
	if ((pci_probe & PCI_PROBE_CONF2) == 0)
		return 0;
	if (!request_region(0xCF8, 4, "PCI conf2"))
		return 0;
	if (!request_region(0xC000, 0x1000, "PCI conf2"))
		goto fail2;

	if (pci_check_type2()) {
		raw_pci_ops = &pci_direct_conf2;
		port_cf9_safe = true;
		return 2;
	}

	release_region(0xC000, 0x1000);
fail2:
	release_region(0xCF8, 4);
	return 0;
}
