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
#include <lego/delay.h>
#include <lego/timer.h>
#include <lego/kernel.h>
#include <lego/resource.h>

#include <asm/io.h>

#include "pci.h"

struct pci_dynid {
	struct list_head node;
	struct pci_device_id id;
};

/**
 * pci_match_id - See if a pci device matches a given pci_id table
 * @ids: array of PCI device id structures to search in
 * @dev: the PCI device structure to match against.
 *
 * Used by a driver to check whether a PCI device present in the
 * system is in its list of supported devices.  Returns the matching
 * pci_device_id structure or %NULL if there is no match.
 *
 * Deprecated, don't use this as it will not catch any dynamic ids
 * that a driver might want to check for.
 */
const struct pci_device_id *pci_match_id(const struct pci_device_id *ids,
					 struct pci_dev *dev)
{
	if (ids) {
		while (ids->vendor || ids->subvendor || ids->class_mask) {
			if (pci_match_one_device(ids, dev))
				return ids;
			ids++;
		}
	}
	return NULL;
}

/**
 * pci_match_device - Tell if a PCI device structure has a matching PCI device id structure
 * @drv: the PCI driver to match against
 * @dev: the PCI device structure to match against
 *
 * Used by a driver to check whether a PCI device present in the
 * system is in its list of supported devices.  Returns the matching
 * pci_device_id structure or %NULL if there is no match.
 */
static const struct pci_device_id *pci_match_device(struct pci_driver *drv,
						    struct pci_dev *dev)
{
	struct pci_dynid *dynid;

	/*
	 * Look at the dynamic ids first, before the static ones
	 * For lego, remember we don't have the dynids thing,
	 * we go down to pci_match_id() directly.
	 */
	spin_lock(&drv->dynids.lock);
	list_for_each_entry(dynid, &drv->dynids.list, node) {
		if (pci_match_one_device(&dynid->id, dev)) {
			spin_unlock(&drv->dynids.lock);
			return &dynid->id;
		}
	}
	spin_unlock(&drv->dynids.lock);

	return pci_match_id(drv->id_table, dev);
}

/**
 * pci_bus_match - Tell if a PCI device structure has a matching PCI device id structure
 * @dev: the PCI device structure to match against
 * @drv: the device driver to search for matching PCI device id structures
 *
 * Used by a driver to check whether a PCI device present in the
 * system is in its list of supported devices. Returns the matching
 * pci_device_id structure or %NULL if there is no match.
 */
static int pci_bus_match(struct device *dev, struct device_driver *drv)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct pci_driver *pci_drv;
	const struct pci_device_id *found_id;

	pci_drv = to_pci_driver(drv);
	found_id = pci_match_device(pci_drv, pci_dev);
	if (found_id)
		return 1;

	return 0;
}

/**
 * pci_register_driver - register a new pci driver
 * @drv: the driver structure to register
 * @owner: owner module of drv
 * 
 * Adds the driver structure to the list of registered drivers.
 * Returns a negative value on error, otherwise 0. 
 * If no error occurred, the driver remains registered even if 
 * no device was claimed during registration.
 */
int pci_register_driver(struct pci_driver *pdrv)
{
	struct pci_dev *pdev = NULL;

	/* initialize common driver fields */
	pdrv->driver.name = pdrv->name;
	pdrv->driver.bus = &pci_bus_type;

	spin_lock_init(&pdrv->dynids.lock);
	INIT_LIST_HEAD(&pdrv->dynids.list);

	for_each_pci_dev(pdev) {
		const struct pci_device_id *pid;
		int ret;

		pid = pci_match_device(pdrv, pdev);
		if (!pid)
			continue;

		ret = pdrv->probe(pdev, pid);
		return ret;
	}
	return 0;
}

static int pci_device_probe(struct device * dev)
{
	return 0;
}

static int pci_device_remove(struct device * dev)
{
	return 0;
}

static void pci_device_shutdown(struct device *dev)
{
	return;
}

struct bus_type pci_bus_type = {
	.name		= "pci",
	.match		= pci_bus_match,
	.probe		= pci_device_probe,
	.remove		= pci_device_remove,
	.shutdown	= pci_device_shutdown,
};
