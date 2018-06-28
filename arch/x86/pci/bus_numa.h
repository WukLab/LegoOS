/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __BUS_NUMA_H
#define __BUS_NUMA_H

#include <lego/list.h>
#include <lego/resource.h>

/*
 * sub bus (transparent) will use entres from 3 to store extra from
 * root, so need to make sure we have enough slot there.
 */
struct pci_root_res {
	struct list_head list;
	struct resource res;
};

struct pci_root_info {
	struct list_head list;
	char name[12];
	struct list_head resources;
	struct resource busn;
	int node;
	int link;
};

extern struct list_head pci_root_infos;
struct pci_root_info *alloc_pci_root_info(int bus_min, int bus_max,
						int node, int link);
extern void update_res(struct pci_root_info *info, resource_size_t start,
		      resource_size_t end, unsigned long flags, int merge);

void x86_pci_root_bus_resources(int bus, struct list_head *resources);

#endif
