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

static int default_apic_id_valid(int apicid)
{
	return (apicid < 255);
}

static unsigned int flat_get_apic_id(unsigned long x)
{
	return (x >> 24) & 0xFF;
}

static unsigned long set_apic_id(unsigned int id)
{
	return (id & 0xFF) << 24;
}

static int flat_probe(void)
{
	return 1;
}

static struct apic apic_flat = {
	.name				= "flat",
	.probe				= flat_probe,
	.apic_id_valid			= default_apic_id_valid,

	.irq_delivery_mode		= dest_LowestPrio,
	.irq_dest_mode			= 1, /* Logical */

	.get_apic_id			= flat_get_apic_id,
	.set_apic_id			= set_apic_id,

/*
	.send_IPI			= default_send_IPI_single,
	.send_IPI_mask			= flat_send_IPI_mask,
	.send_IPI_mask_allbutself	= flat_send_IPI_mask_allbutself,
	.send_IPI_allbutself		= flat_send_IPI_allbutself,
	.send_IPI_all			= flat_send_IPI_all,
	.send_IPI_self			= apic_send_IPI_self,

	.read				= native_apic_mem_read,
	.write				= native_apic_mem_write,
	.eoi_write			= native_apic_mem_write,
	.icr_read			= native_apic_icr_read,
	.icr_write			= native_apic_icr_write,
	.wait_icr_idle			= native_apic_wait_icr_idle,
	.safe_wait_icr_idle		= native_safe_apic_wait_icr_idle,
*/
};

static int physflat_probe(void)
{
	return 1;
}

/*
 * Physflat mode is used when there are more than 8 CPUs on a system.
 * We cannot use logical delivery in this case because the mask
 * overflows, so use physical mode.
 */
static struct apic apic_physflat = {
	.name				= "physical flat",
	.probe				= physflat_probe,
	.apic_id_valid			= default_apic_id_valid,

	.irq_delivery_mode		= dest_Fixed,
	.irq_dest_mode			= 0, /* Logical */

	.get_apic_id			= flat_get_apic_id,
	.set_apic_id			= set_apic_id,

/*
	.send_IPI			= default_send_IPI_single_phys,
	.send_IPI_mask			= default_send_IPI_mask_sequence_phys,
	.send_IPI_mask_allbutself	= default_send_IPI_mask_allbutself_phys,
	.send_IPI_allbutself		= physflat_send_IPI_allbutself,
	.send_IPI_all			= physflat_send_IPI_all,
	.send_IPI_self			= apic_send_IPI_self,

	.read				= native_apic_mem_read,
	.write				= native_apic_mem_write,
	.eoi_write			= native_apic_mem_write,
	.icr_read			= native_apic_icr_read,
	.icr_write			= native_apic_icr_write,
	.wait_icr_idle			= native_apic_wait_icr_idle,
	.safe_wait_icr_idle		= native_safe_apic_wait_icr_idle,
*/
};

struct apic *apic __read_mostly = &apic_flat;

/*
 * We need to check for physflat first,
 * so this order is important.
 */
apic_drivers(apic_physflat, apic_flat);
