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
#include <lego/kernel.h>

void pci_add_resource_offset(struct list_head *resources, struct resource *res,
			     resource_size_t offset)
{
	struct pci_host_bridge_window *window;

	window = kzalloc(sizeof(struct pci_host_bridge_window), GFP_KERNEL);
	if (!window) {
		printk(KERN_ERR "PCI: can't add host bridge window %pR\n", res);
		return;
	}

	window->res = res;
	window->offset = offset;
	list_add_tail(&window->list, resources);
}

void pci_add_resource(struct list_head *resources, struct resource *res)
{
	pci_add_resource_offset(resources, res, 0);
}

void pci_free_resource_list(struct list_head *resources)
{
	struct pci_host_bridge_window *window, *tmp;

	list_for_each_entry_safe(window, tmp, resources, list) {
		list_del(&window->list);
		kfree(window);
	}
}
