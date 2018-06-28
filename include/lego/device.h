/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * device.h - generic, centralized driver model
 *
 * Copyright (c) 2001-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (c) 2004-2009 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2008-2009 Novell Inc.
 *
 * This file is released under the GPLv2
 *
 * See Documentation/driver-model/ for more information.
 */

#ifndef _LEGO_DEVICE_H_
#define _LEGO_DEVICE_H_

#include <lego/kernel.h>

#define MAX_DEVICE_NAME		(64)

struct device;

struct device_driver {
	char			name[MAX_DEVICE_NAME];
	const char		*mod_name;

	int (*probe) (struct device *dev);
	int (*remove) (struct device *dev);
	void (*shutdown) (struct device *dev);
};

struct device {
	struct device	*parent;
	char		name[MAX_DEVICE_NAME];

	struct device_driver *driver;	/* which driver has allocated this
					   device */
	void		*platform_data;	/* Platform specific data, device
					   core doesn't touch it */
#ifdef CONFIG_NUMA
	int		numa_node;	/* NUMA node this device is close to */
#endif
	u64		*dma_mask;	/* dma mask (if dma'able device) */
	u64		coherent_dma_mask;/* Like dma_mask, but for
					     alloc_coherent mappings as
					     not all hardware supports
					     64 bit addresses for consistent
					     allocations such descriptors. */

	void	(*release)(struct device *dev);
};

/**
 * dev_set_name - set a device name
 * @dev: device
 * @fmt: format string for the device's name
 */
static inline int dev_set_name(struct device *dev, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsnprintf(dev->name, MAX_DEVICE_NAME, fmt, args);
	va_end(args);

	return i;
}

#endif /* _LEGO_DEVICE_H_ */
