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

#if 0
#ifndef _DEVICE_H_
#define _DEVICE_H_

//typedef struct pm_message {
//        int event;
//} pm_message_t;

struct device;

struct device_driver {
	//struct bus_type		*bus;

	//enum probe_type probe_type;

	//const struct of_device_id	*of_match_table;
	//const struct acpi_device_id	*acpi_match_table;

	int (*probe) (struct device *dev);
	int (*remove) (struct device *dev);
	void (*shutdown) (struct device *dev);
	//int (*suspend) (struct device *dev, pm_message_t state);
	//int (*resume) (struct device *dev);
	//const struct attribute_group **groups;

	//const struct dev_pm_ops *pm;

};

struct device {
	u32		id;	/* device instance */
	u64		*dma_mask;	/* dma mask (if dma'able device) */
	u64		*coherent_dma_mask;	/* dma mask alloc_coherent mappings */
	struct device_driver *driver;	/* which driver has allocated this
					   device */
}

#endif /* _DEVICE_H_ */
#endif
