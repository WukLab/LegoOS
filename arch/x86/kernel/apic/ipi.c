/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * YS: 11/28/17
 * APIC supports 3 different shortcuts to broadcast IPI to cores.
 * They are self, all including self, all excluding self. This is
 * described by __default_send_IPI_shortcut() function.
 *
 * APIC also let us to specify the destination CPU's APICID, thus
 * send IPI to one specific CPU. This is described by the following
 * __default_send_IPI_dest_field() function.
 *
 * However, there is no way to send to a set of CPUs at the same time.
 * It means APIC by itself can not handle a cpumask. What Lego or Linux
 * doing here is to send IPI one by one.
 *
 * Probabaly cluster mode APIC can handle this, but who is using that?
 */

#include <asm/ipi.h>
#include <asm/apic.h>

#include <lego/irq.h>
#include <lego/smp.h>
#include <lego/kernel.h>

void __default_send_IPI_shortcut(unsigned int shortcut, int vector, unsigned int dest)
{
	/*
	 * Subtle. In the case of the 'never do double writes' workaround
	 * we have to lock out interrupts to be safe.  As we don't care
	 * of the value read we use an atomic rmw access to avoid costly
	 * cli/sti.  Otherwise we use an even cheaper single atomic write
	 * to the APIC.
	 */
	unsigned int cfg;

	/*
	 * Wait for idle.
	 */
	__xapic_wait_icr_idle();

	/*
	 * No need to touch the target chip field
	 */
	cfg = __prepare_ICR(shortcut, vector, dest);

	/*
	 * Send the IPI. The write to APIC_ICR fires this off.
	 */
	native_apic_mem_write(APIC_ICR, cfg);
}

/*
 * This is used to send an IPI with no shorthand notation (the destination is
 * specified in bits 56 to 63 of the ICR).
 */
void __default_send_IPI_dest_field(unsigned int mask, int vector, unsigned int dest)
{
	unsigned long cfg;

	/*
	 * Wait for idle.
	 */
	if (unlikely(vector == NMI_VECTOR))
		safe_apic_wait_icr_idle();
	else
		__xapic_wait_icr_idle();

	/*
	 * prepare target chip field
	 */
	cfg = __prepare_ICR2(mask);
	native_apic_mem_write(APIC_ICR2, cfg);

	/*
	 * program the ICR
	 */
	cfg = __prepare_ICR(0, vector, dest);

	/*
	 * Send the IPI. The write to APIC_ICR fires this off.
	 */
	native_apic_mem_write(APIC_ICR, cfg);
}

static inline unsigned int x86_cpu_to_apicid(int cpu)
{
	return cpu_to_apicid(cpu);
}

void default_send_IPI_single_phys(int cpu, int vector)
{
	unsigned long flags;

	local_irq_save(flags);
	__default_send_IPI_dest_field(x86_cpu_to_apicid(cpu),
				      vector, APIC_DEST_PHYSICAL);
	local_irq_restore(flags);
}

void default_send_IPI_mask_sequence_phys(const struct cpumask *mask, int vector)
{
	unsigned long query_cpu;
	unsigned long flags;

	/*
	 * Hack. The clustered APIC addressing mode doesn't allow us to send
	 * to an arbitrary mask, so I do a unicast to each CPU instead.
	 * - mbligh
	 */
	local_irq_save(flags);
	for_each_cpu(query_cpu, mask) {
		__default_send_IPI_dest_field(x86_cpu_to_apicid(query_cpu),
					vector, APIC_DEST_PHYSICAL);
	}
	local_irq_restore(flags);
}

void default_send_IPI_mask_allbutself_phys(const struct cpumask *mask,
						 int vector)
{
	unsigned int this_cpu = smp_processor_id();
	unsigned int query_cpu;
	unsigned long flags;

	/* See Hack comment above */

	local_irq_save(flags);
	for_each_cpu(query_cpu, mask) {
		if (query_cpu == this_cpu)
			continue;
		__default_send_IPI_dest_field(x86_cpu_to_apicid(query_cpu),
					vector, APIC_DEST_PHYSICAL);
	}
	local_irq_restore(flags);
}

/*
 * Helper function for APICs which insist on cpumasks
 */
void default_send_IPI_single(int cpu, int vector)
{
	apic->send_IPI_mask(cpumask_of(cpu), vector);
}
