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
#include <lego/range.h>
#include <lego/kernel.h>
#include <lego/resource.h>

#include <asm/io_apic.h>

static int pirq_enable_irq(struct pci_dev *dev);

int (*pcibios_enable_irq)(struct pci_dev *dev) = pirq_enable_irq;

static int pirq_enable_irq(struct pci_dev *dev)
{
	u8 pin;

	pci_read_config_byte(dev, PCI_INTERRUPT_PIN, &pin);
	pr_info("(dev %s) enable_irq pin: %d\n", dev_name(&dev->dev), pin);
	if (pin) {
		char *msg  = "";

		if (1) {
#ifdef CONFIG_X86_IO_APIC
			struct pci_dev *temp_dev;
			int irq;

			if (dev->irq_managed && dev->irq > 0)
				return 0;

			irq = IO_APIC_get_PCI_irq_vector(dev->bus->number,
						PCI_SLOT(dev->devfn), pin - 1);
			temp_dev = dev;
			while (irq < 0 && dev->bus->parent) { /* go back to the bridge */
				struct pci_dev *bridge = dev->bus->self;

				pin = pci_swizzle_interrupt_pin(dev, pin);
				irq = IO_APIC_get_PCI_irq_vector(bridge->bus->number,
						PCI_SLOT(bridge->devfn),
						pin - 1);
				if (irq >= 0)
					dev_warn(&dev->dev, "using bridge %s "
						 "INT %c to get IRQ %d\n",
						 pci_name(bridge), 'A' + pin - 1,
						 irq);
				dev = bridge;
			}
			dev = temp_dev;
			if (irq >= 0) {
				dev->irq_managed = 1;
				dev->irq = irq;
				pr_info("(dev %s) PCI->APIC IRQ transform: "
					 "INT %c -> IRQ %d\n", dev_name(&dev->dev),
					 'A' + pin - 1, irq);
				return 0;
			} else
				msg = "; probably buggy MP table";
#endif
		}

		/*
		 * With IDE legacy devices the IRQ lookup failure is not
		 * a problem..
		 */
		if (dev->class >> 8 == PCI_CLASS_STORAGE_IDE &&
				!(dev->class & 0x5))
			return 0;

		pr_warn("(dev %s)can't find IRQ for PCI INT %c%s\n",
			dev_name(&dev->dev), 'A' + pin - 1, msg);
	}
	return 0;
}
