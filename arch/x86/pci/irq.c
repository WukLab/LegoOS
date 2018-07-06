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

static int pirq_enable_irq(struct pci_dev *dev);

int (*pcibios_enable_irq)(struct pci_dev *dev) = pirq_enable_irq;

static int pirq_enable_irq(struct pci_dev *dev)
{
	pr_info_once("%s(): TODO\n", __func__);
	return 0;
}
