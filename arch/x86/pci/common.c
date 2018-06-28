/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/pci.h>
#include <lego/slab.h>
#include <lego/list.h>
#include <lego/kernel.h>
#include <asm/pci.h>

unsigned int pci_probe = PCI_PROBE_BIOS | PCI_PROBE_CONF1 | PCI_PROBE_CONF2 |
				PCI_PROBE_MMCONF;

int pcibios_last_bus = -1;

/*
 * This pci_raw_ops are the lowest-level PCI access ops.
 * x86 has this indirection because it has some different variant methods.
 * We choose one at early boot by pci_arch_init().
 */
const struct pci_raw_ops *__read_mostly raw_pci_ops;
const struct pci_raw_ops *__read_mostly raw_pci_ext_ops;

int raw_pci_read(unsigned int domain, unsigned int bus, unsigned int devfn,
						int reg, int len, u32 *val)
{
	if (domain == 0 && reg < 256 && raw_pci_ops)
		return raw_pci_ops->read(domain, bus, devfn, reg, len, val);
	if (raw_pci_ext_ops)
		return raw_pci_ext_ops->read(domain, bus, devfn, reg, len, val);
	return -EINVAL;
}

int raw_pci_write(unsigned int domain, unsigned int bus, unsigned int devfn,
						int reg, int len, u32 val)
{
	if (domain == 0 && reg < 256 && raw_pci_ops)
		return raw_pci_ops->write(domain, bus, devfn, reg, len, val);
	if (raw_pci_ext_ops)
		return raw_pci_ext_ops->write(domain, bus, devfn, reg, len, val);
	return -EINVAL;
}

static int pci_read(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 *value)
{
	return raw_pci_read(pci_domain_nr(bus), bus->number,
				 devfn, where, size, value);
}

static int pci_write(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 value)
{
	return raw_pci_write(pci_domain_nr(bus), bus->number,
				  devfn, where, size, value);
}

/*
 * This pci_ops is exposed to core pci sub-system
 * Upper layer code should use this.
 */
struct pci_ops pci_root_ops __read_mostly = {
	.read = pci_read,
	.write = pci_write,
};

/*
 * This should be the first function called in PCI initlization part.
 * This function will determines the configuration space access method.
 */
static void __init pci_arch_init(void)
{
#ifdef CONFIG_PCI_DIRECT
	int type = 0;

	/*
	 * Check if we can use type 1 or type 2 hardware direct access.
	 * Mostly, she will say Yes.
	 */
	type = pci_direct_probe();
#endif

	if (!(pci_probe & PCI_PROBE_NOEARLY))
		pci_mmcfg_early_init();

	/*
	 * Skip the PCI BIOS part.
	 * Who need this shit to access PCI?
	 * (https://wiki.osdev.org/BIOS32)
	 */

#ifdef CONFIG_PCI_DIRECT
	pci_direct_init(type);
#endif

	/*
	 * Lego simply can NOT live without PCI
	 * Because we need NICs..
	 */
	if (!raw_pci_ops && !raw_pci_ext_ops)
		panic("PCI: Fatal: No config space access function found\n");
}

void __init pci_subsys_init(void)
{
	pci_arch_init();


	panic("asd");
}
