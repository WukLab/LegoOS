/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/irq.h>
#include <lego/time.h>
#include <lego/kernel.h>

#include <asm/io.h>
#include <asm/hpet.h>
#include <asm/apic.h>

/* HPET address is set by ACPI, when an ACPI entry exists */
unsigned long hpet_address;

/* OS timer block num */
u8 hpet_blockid;

static unsigned long hpet_freq;
static void __iomem *hpet_virt_address;

inline unsigned int hpet_readl(unsigned int a)
{
	return readl(hpet_virt_address + a);
}

static inline void hpet_writel(unsigned int d, unsigned int a)
{
	writel(d, hpet_virt_address + a);
}

bool hpet_verbose = true;

static void _hpet_print_config(const char *function, int line)
{
	u32 i, timers, l, h;
	printk(KERN_INFO "hpet: %s(%d):\n", function, line);
	l = hpet_readl(HPET_ID);
	h = hpet_readl(HPET_PERIOD);
	timers = ((l & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT) + 1;
	printk(KERN_INFO "hpet: ID: 0x%x, PERIOD: 0x%x\n", l, h);
	l = hpet_readl(HPET_CFG);
	h = hpet_readl(HPET_STATUS);
	printk(KERN_INFO "hpet: CFG: 0x%x, STATUS: 0x%x\n", l, h);
	l = hpet_readl(HPET_COUNTER);
	h = hpet_readl(HPET_COUNTER+4);
	printk(KERN_INFO "hpet: COUNTER_l: 0x%x, COUNTER_h: 0x%x\n", l, h);

	for (i = 0; i < timers; i++) {
		l = hpet_readl(HPET_Tn_CFG(i));
		h = hpet_readl(HPET_Tn_CFG(i)+4);
		printk(KERN_INFO "hpet: T%d: CFG_l: 0x%x, CFG_h: 0x%x\n",
		       i, l, h);
		l = hpet_readl(HPET_Tn_CMP(i));
		h = hpet_readl(HPET_Tn_CMP(i)+4);
		printk(KERN_INFO "hpet: T%d: CMP_l: 0x%x, CMP_h: 0x%x\n",
		       i, l, h);
		l = hpet_readl(HPET_Tn_ROUTE(i));
		h = hpet_readl(HPET_Tn_ROUTE(i)+4);
		printk(KERN_INFO "hpet: T%d ROUTE_l: 0x%x, ROUTE_h: 0x%x\n",
		       i, l, h);
	}
}

#define hpet_print_config()					\
do {								\
	if (hpet_verbose)					\
		_hpet_print_config(__func__, __LINE__);	\
} while (0)

static inline void hpet_set_mapping(void)
{
	hpet_virt_address = ioremap_nocache(hpet_address, HPET_MMAP_SIZE);
}

static inline void hpet_clear_mapping(void)
{
	iounmap(hpet_virt_address);
	hpet_virt_address = NULL;
}

/**
 * hpet_enable
 *
 * Try to setup the HPET timer.
 * Returns 0 on success.
 */
int hpet_enable(void)
{
	u32 hpet_period, cfg, id;
	u64 freq;
	unsigned int i, last;

	if (hpet_address)
		return -ENODEV;

	hpet_set_mapping();

	/*
	 * Read the period and check for a sane value:
	 */
	hpet_period = hpet_readl(HPET_PERIOD);

	if (hpet_period < HPET_MIN_PERIOD || hpet_period > HPET_MAX_PERIOD)
		goto out_nohpet;

	/*
	 * The period is a femto seconds value. Convert it to a
	 * frequency.
	 */
	freq = FSEC_PER_SEC;
	do_div(freq, hpet_period);
	hpet_freq = freq;

	/*
	 * Read the HPET ID register to retrieve the IRQ routing
	 * information and the number of channels
	 */
	id = hpet_readl(HPET_ID);
	hpet_print_config();

	last = (id & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT;

	return 0;

out_nohpet:
	return -ENODEV;
}
