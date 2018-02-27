/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file describes flat APIC mode, including logical and physical.
 * Lego currently does not support cluster mode or any other special chips.
 * Those things are really fun to play with.	YS. 11/27/17
 */

#include <asm/asm.h>
#include <asm/ipi.h>
#include <asm/apic.h>
#include <asm/fixmap.h>
#include <asm/processor.h>

#include <lego/irq.h>
#include <lego/smp.h>
#include <lego/kernel.h>
#include <lego/bitops.h>

static struct apic apic_physflat;
static struct apic apic_flat;

/* By default, use the LogicalFlat model */
struct apic *apic __read_mostly = &apic_flat;

/* Same for both flat and physical. */
static void default_apic_send_IPI_self(int vector)
{
	__default_send_IPI_shortcut(APIC_DEST_SELF, vector, APIC_DEST_PHYSICAL);
}

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

static void _flat_send_IPI_mask(unsigned long mask, int vector)
{
	unsigned long flags;

	local_irq_save(flags);
	__default_send_IPI_dest_field(mask, vector, apic->dest_logical);
	local_irq_restore(flags);
}

static void flat_send_IPI_mask(const struct cpumask *cpumask, int vector)
{
	unsigned long mask = cpumask_bits(cpumask)[0];

	_flat_send_IPI_mask(mask, vector);
}

static void
flat_send_IPI_mask_allbutself(const struct cpumask *cpumask, int vector)
{
	unsigned long mask = cpumask_bits(cpumask)[0];
	int cpu = smp_processor_id();

	if (cpu < BITS_PER_LONG)
		clear_bit(cpu, &mask);

	_flat_send_IPI_mask(mask, vector);
}

static void flat_send_IPI_allbutself(int vector)
{
	int cpu = smp_processor_id();
#ifdef	CONFIG_HOTPLUG_CPU
	int hotplug = 1;
#else
	int hotplug = 0;
#endif
	if (hotplug || vector == NMI_VECTOR) {
		if (!cpumask_equal(cpu_online_mask, cpumask_of(cpu))) {
			unsigned long mask = cpumask_bits(cpu_online_mask)[0];

			if (cpu < BITS_PER_LONG)
				clear_bit(cpu, &mask);

			_flat_send_IPI_mask(mask, vector);
		}
	} else if (num_online_cpus() > 1) {
		__default_send_IPI_shortcut(APIC_DEST_ALLBUT,
					    vector, apic->dest_logical);
	}
}

static void flat_send_IPI_all(int vector)
{
	if (vector == NMI_VECTOR) {
		flat_send_IPI_mask(cpu_online_mask, vector);
	} else {
		__default_send_IPI_shortcut(APIC_DEST_ALLINC,
					    vector, apic->dest_logical);
	}
}

static int flat_probe(void)
{
	return 1;
}

/*
 * Set up the logical destination ID.
 *
 * Intel recommends to set DFR, LDR and TPR before enabling
 * an APIC.  See e.g. "AP-388 82489DX User's Manual" (Intel
 * document number 292116).  So here it goes...
 */
void flat_init_apic_ldr(void)
{
	unsigned long val;
	unsigned long num, id;

	num = smp_processor_id();
	id = 1UL << num;
	apic_write(APIC_DFR, APIC_DFR_FLAT);
	val = apic_read(APIC_LDR) & ~APIC_LDR_MASK;
	val |= SET_APIC_LOGICAL_ID(id);
	apic_write(APIC_LDR, val);
}

static const struct cpumask *online_target_cpus(void)
{
	return cpu_online_mask;
}

static void
flat_vector_allocation_domain(int cpu, struct cpumask *retmask,
			      const struct cpumask *mask)
{
	/* Careful. Some cpus do not strictly honor the set of cpus
	 * specified in the interrupt destination when using lowest
	 * priority interrupt delivery mode.
	 *
	 * In particular there was a hyperthreading cpu observed to
	 * deliver interrupts to the wrong hyperthread when only one
	 * hyperthread was specified in the interrupt desitination.
	 */
	cpumask_clear(retmask);
	cpumask_bits(retmask)[0] = APIC_ALL_CPUS;
}

static void
default_vector_allocation_domain(int cpu, struct cpumask *retmask,
				 const struct cpumask *mask)
{
	cpumask_copy(retmask, cpumask_of(cpu));
}

static int
flat_cpu_mask_to_apicid_and(const struct cpumask *cpumask,
			    const struct cpumask *andmask,
			    unsigned int *apicid)
{
	unsigned long cpu_mask = cpumask_bits(cpumask)[0] &
				 cpumask_bits(andmask)[0] &
				 cpumask_bits(cpu_online_mask)[0] &
				 APIC_ALL_CPUS;

	if (likely(cpu_mask)) {
		*apicid = (unsigned int)cpu_mask;
		return 0;
	} else {
		return -EINVAL;
	}
}

static int
default_cpu_mask_to_apicid_and(const struct cpumask *cpumask,
			       const struct cpumask *andmask,
			       unsigned int *apicid)
{
	unsigned int cpu;

	for_each_cpu_and(cpu, cpumask, andmask) {
		if (cpumask_test_cpu(cpu, cpu_online_mask))
			break;
	}

	if (likely(cpu < nr_cpu_ids)) {
		*apicid = cpu_to_apicid(cpu);
		return 0;
	}

	return -EINVAL;
}

static int flat_phys_pkg_id(int initial_apic_id, int index_msb)
{
	return initial_apic_id >> index_msb;
}

/*
 * YS:
 * According to Intel SDM vol3, sec 10.6.2.2 Logical Destination Mode,
 * flat mode (logical) can only support up to 8 local APICs, which means
 * at most 8 CPUs.
 *
 * This flat mode is better named as:
 * 	LogicalFlat
 */
static struct apic apic_flat = {
	.name				= "logical flat",
	.probe				= flat_probe,
	.apic_id_valid			= default_apic_id_valid,

	.irq_delivery_mode		= dest_LowestPrio,
	.irq_dest_mode			= 1, /* Logical Mode */

	.target_cpus			= online_target_cpus,

	.dest_logical			= APIC_DEST_LOGICAL,

	.get_apic_id			= flat_get_apic_id,
	.set_apic_id			= set_apic_id,

	.vector_allocation_domain	= flat_vector_allocation_domain,
	.init_apic_ldr			= flat_init_apic_ldr,

	.phys_pkg_id			= flat_phys_pkg_id,

	.cpu_mask_to_apicid_and		= flat_cpu_mask_to_apicid_and,

	.send_IPI			= default_send_IPI_single,
	.send_IPI_mask			= flat_send_IPI_mask,
	.send_IPI_mask_allbutself	= flat_send_IPI_mask_allbutself,
	.send_IPI_allbutself		= flat_send_IPI_allbutself,
	.send_IPI_all			= flat_send_IPI_all,
	.send_IPI_self			= default_apic_send_IPI_self,

	.read				= native_apic_mem_read,
	.write				= native_apic_mem_write,
	.eoi_write			= native_apic_mem_write,
	.icr_read			= native_apic_icr_read,
	.icr_write			= native_apic_icr_write,
	.wait_icr_idle			= native_apic_wait_icr_idle,
	.safe_wait_icr_idle		= native_safe_apic_wait_icr_idle,
};

static void physflat_send_IPI_allbutself(int vector)
{
	default_send_IPI_mask_allbutself_phys(cpu_online_mask, vector);
}

static void physflat_send_IPI_all(int vector)
{
	default_send_IPI_mask_sequence_phys(cpu_online_mask, vector);
}

/*
 * Physflat mode is used when there are more than 8 CPUs on a system.
 * We cannot use logical delivery in this case because the mask
 * overflows, so use physical mode.
 *
 * (See my comment above apic_flat)
 */
static int physflat_probe(void)
{
	if (apic == &apic_physflat || num_possible_cpus() > 8)
		return 1;
	return 0;
}

static struct apic apic_physflat = {
	.name				= "physical flat",
	.probe				= physflat_probe,
	.apic_id_valid			= default_apic_id_valid,

	.irq_delivery_mode		= dest_Fixed,
	.irq_dest_mode			= 0, /* Physical Mode */

	.dest_logical			= 0,

	.target_cpus			= online_target_cpus,

	.get_apic_id			= flat_get_apic_id,
	.set_apic_id			= set_apic_id,

	.vector_allocation_domain	= default_vector_allocation_domain,
	/* not needed, but shouldn't hurt: */
	.init_apic_ldr			= flat_init_apic_ldr,

	.phys_pkg_id			= flat_phys_pkg_id,

	.cpu_mask_to_apicid_and		= default_cpu_mask_to_apicid_and,

	.send_IPI			= default_send_IPI_single_phys,
	.send_IPI_mask			= default_send_IPI_mask_sequence_phys,
	.send_IPI_mask_allbutself	= default_send_IPI_mask_allbutself_phys,
	.send_IPI_allbutself		= physflat_send_IPI_allbutself,
	.send_IPI_all			= physflat_send_IPI_all,
	.send_IPI_self			= default_apic_send_IPI_self,

	.read				= native_apic_mem_read,
	.write				= native_apic_mem_write,
	.eoi_write			= native_apic_mem_write,
	.icr_read			= native_apic_icr_read,
	.icr_write			= native_apic_icr_write,
	.wait_icr_idle			= native_apic_wait_icr_idle,
	.safe_wait_icr_idle		= native_safe_apic_wait_icr_idle,
};

/*
 * We need to check for physflat first,
 * so this order is important.
 */
apic_drivers(apic_physflat, apic_flat);
