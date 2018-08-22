/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/pci.h>
#include <lego/device.h>
#include <lego/kernel.h>

void __init ib_core_init(void);

/*
 * This is called after PCI init.
 * Please put any device init code here.
 */
void __init device_init(void)
{
	ib_core_init();
}

static int __dev_printk(const char *level, const struct device *dev,
			struct va_format *vaf)
{
	if (!dev)
		return printk("(NULL device *): %pV", vaf);

	return printk("(dev %s): %pV", dev_name(dev), vaf);
}

int dev_printk(const char *level, const struct device *dev,
	       const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;
	int r;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	r = __dev_printk(level, dev, &vaf);

	va_end(args);

	return r;
}

#define define_dev_printk_level(func, kern_level)		\
int func(const struct device *dev, const char *fmt, ...)	\
{								\
	struct va_format vaf;					\
	va_list args;						\
	int r;							\
								\
	va_start(args, fmt);					\
								\
	vaf.fmt = fmt;						\
	vaf.va = &args;						\
								\
	r = __dev_printk(kern_level, dev, &vaf);		\
								\
	va_end(args);						\
								\
	return r;						\
}

define_dev_printk_level(dev_emerg, KERN_EMERG);
define_dev_printk_level(dev_alert, KERN_ALERT);
define_dev_printk_level(dev_crit, KERN_CRIT);
define_dev_printk_level(dev_err, KERN_ERR);
define_dev_printk_level(dev_warn, KERN_WARNING);
define_dev_printk_level(dev_notice, KERN_NOTICE);
define_dev_printk_level(_dev_info, KERN_INFO);

void device_initialize(struct device *dev)
{
	INIT_LIST_HEAD(&dev->dma_pools);
	set_dev_node(dev, 0);
}
