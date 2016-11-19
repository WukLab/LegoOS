/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <asm/asm.h>
#include <asm/apic.h>
#include <asm/processor.h>

#include <lego/kernel.h>
#include <lego/bitops.h>

static int flat_probe(void)
{
	return 1;
}

static struct apic apic_flat = {
	.name		= "flat",
	.probe		= flat_probe,
};

static int physflat_probe(void)
{
	return 1;
}

static struct apic apic_physflat = {
	.name		= "physical flat",
	.probe		= physflat_probe,
};

struct apic *apic __read_mostly = &apic_flat;

/*
 * We need to check for physflat first,
 * so this order is important.
 */
apic_drivers(apic_physflat, apic_flat);
