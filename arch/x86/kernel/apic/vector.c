/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/irq.h>
#include <lego/slab.h>
#include <lego/irqdesc.h>
#include <lego/irqdomain.h>
#include <lego/spinlock.h>
#include <lego/cpumask.h>

#include <asm/desc.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/numa.h>
#include <asm/i8259.h>
#include <asm/hw_irq.h>
#include <asm/irq_vectors.h>

struct apic_chip_data {
	struct irq_cfg		cfg;
	cpumask_var_t		domain;
	cpumask_var_t		old_domain;
	u8			move_in_progress : 1;
};

#ifdef CONFIG_X86_IO_APIC
static struct apic_chip_data legacy_irq_data[NR_IRQS_LEGACY];
#endif

static DEFINE_SPINLOCK(vector_lock);
static cpumask_var_t vector_cpumask, vector_searchmask, searched_cpumask;

static inline struct apic_chip_data *
apic_chip_data(struct irq_data *irq_data)
{
	if (!irq_data)
		return NULL;

	/*
	 * The first irq_data actually is used by io-apic
	 * the irq_data->parent_data is the real one that
	 * points to apic_chip_data.
	 */
	while (irq_data->parent_data)
		irq_data = irq_data->parent_data;

	return irq_data->chip_data;
}

struct irq_cfg *irqd_cfg(struct irq_data *irq_data)
{
	struct apic_chip_data *data;

	data = apic_chip_data(irq_data);
	return data ? &data->cfg : NULL;
}

struct irq_cfg *irq_cfg(unsigned int irq)
{
	return irqd_cfg(irq_get_irq_data(irq));
}

static void clear_irq_vector(int irq, struct apic_chip_data *data)
{
	struct irq_desc *desc;
	int cpu, vector;

	if (!data->cfg.vector)
		return;

	vector = data->cfg.vector;
	for_each_cpu_and(cpu, data->domain, cpu_online_mask) {
		struct irq_desc **vector_irq = per_cpu_vector_irq(cpu);

		vector_irq[vector] = VECTOR_UNUSED;
	}

	data->cfg.vector = 0;
	cpumask_clear(data->domain);

	/*
	 * If move is in progress or the old_domain mask is not empty,
	 * i.e. the cleanup IPI has not been processed yet, we need to remove
	 * the old references to desc from all cpus vector tables.
	 */
	if (!data->move_in_progress && cpumask_empty(data->old_domain))
		return;

	desc = irq_to_desc(irq);
	for_each_cpu_and(cpu, data->old_domain, cpu_online_mask) {
		for (vector = FIRST_EXTERNAL_VECTOR; vector < NR_VECTORS;
		     vector++) {
			struct irq_desc **vector_irq = per_cpu_vector_irq(cpu);

			if (vector_irq[vector] != desc)
				continue;
			vector_irq[vector] = VECTOR_UNUSED;
			break;
		}
	}
	data->move_in_progress = 0;
}

static int __assign_irq_vector(int irq, struct apic_chip_data *d,
			       const struct cpumask *mask)
{
	/*
	 * NOTE! The local APIC isn't very good at handling
	 * multiple interrupts at the same interrupt level.
	 * As the interrupt level is determined by taking the
	 * vector number and shifting that right by 4, we
	 * want to spread these out a bit so that they don't
	 * all fall in the same interrupt level.
	 *
	 * Also, we've got to be careful not to trash gate
	 * 0x80, because int 0x80 is hm, kind of importantish. ;)
	 */
	static int current_vector = FIRST_EXTERNAL_VECTOR + VECTOR_OFFSET_START;
	static int current_offset = VECTOR_OFFSET_START % 16;
	int cpu, vector;

	/*
	 * If there is still a move in progress or the previous move has not
	 * been cleaned up completely, tell the caller to come back later.
	 */
	if (d->move_in_progress ||
	    cpumask_intersects(d->old_domain, cpu_online_mask))
		return -EBUSY;

	/* Only try and allocate irqs on cpus that are present */
	cpumask_clear(d->old_domain);
	cpumask_clear(searched_cpumask);
	cpu = cpumask_first_and(mask, cpu_online_mask);
	while (cpu < nr_cpu_ids) {
		int new_cpu, offset;

		/* Get the possible target cpus for @mask/@cpu from the apic */
		apic->vector_allocation_domain(cpu, vector_cpumask, mask);

		/*
		 * Clear the offline cpus from @vector_cpumask for searching
		 * and verify whether the result overlaps with @mask. If true,
		 * then the call to apic->cpu_mask_to_apicid_and() will
		 * succeed as well. If not, no point in trying to find a
		 * vector in this mask.
		 */
		cpumask_and(vector_searchmask, vector_cpumask, cpu_online_mask);
		if (!cpumask_intersects(vector_searchmask, mask))
			goto next_cpu;

		if (cpumask_subset(vector_cpumask, d->domain)) {
			if (cpumask_equal(vector_cpumask, d->domain))
				goto success;
			/*
			 * Mark the cpus which are not longer in the mask for
			 * cleanup.
			 */
			cpumask_andnot(d->old_domain, d->domain, vector_cpumask);
			vector = d->cfg.vector;
			goto update;
		}

		vector = current_vector;
		offset = current_offset;
next:
		vector += 16;
		if (vector >= FIRST_SYSTEM_VECTOR) {
			offset = (offset + 1) % 16;
			vector = FIRST_EXTERNAL_VECTOR + offset;
		}

		/* If the search wrapped around, try the next cpu */
		if (unlikely(current_vector == vector))
			goto next_cpu;

		if (test_bit(vector, used_vectors))
			goto next;

		for_each_cpu(new_cpu, vector_searchmask) {
			struct irq_desc **vector_irq = per_cpu_vector_irq(new_cpu);

			if (!IS_ERR_OR_NULL(vector_irq[vector]))
				goto next;
		}

		/* Found one! */
		current_vector = vector;
		current_offset = offset;

		/* Schedule the old vector for cleanup on all cpus */
		if (d->cfg.vector)
			cpumask_copy(d->old_domain, d->domain);
		for_each_cpu(new_cpu, vector_searchmask) {
			struct irq_desc **vector_irq = per_cpu_vector_irq(new_cpu);

			vector_irq[vector] = irq_to_desc(irq);
		}
		goto update;

next_cpu:
		/*
		 * We exclude the current @vector_cpumask from the requested
		 * @mask and try again with the next online cpu in the
		 * result. We cannot modify @mask, so we use @vector_cpumask
		 * as a temporary buffer here as it will be reassigned when
		 * calling apic->vector_allocation_domain() above.
		 */
		cpumask_or(searched_cpumask, searched_cpumask, vector_cpumask);
		cpumask_andnot(vector_cpumask, mask, searched_cpumask);
		cpu = cpumask_first_and(vector_cpumask, cpu_online_mask);
		continue;
	}
	return -ENOSPC;

update:
	/*
	 * Exclude offline cpus from the cleanup mask and set the
	 * move_in_progress flag when the result is not empty.
	 */
	cpumask_and(d->old_domain, d->old_domain, cpu_online_mask);
	d->move_in_progress = !cpumask_empty(d->old_domain);
	d->cfg.old_vector = d->move_in_progress ? d->cfg.vector : 0;
	d->cfg.vector = vector;
	cpumask_copy(d->domain, vector_cpumask);
success:
	/*
	 * Cache destination APIC IDs into cfg->dest_apicid. This cannot fail
	 * as we already established, that mask & d->domain & cpu_online_mask
	 * is not empty.
	 */
	BUG_ON(apic->cpu_mask_to_apicid_and(mask, d->domain,
					    &d->cfg.dest_apicid));
	return 0;
}

static int assign_irq_vector(int irq, struct apic_chip_data *data,
			     const struct cpumask *mask)
{
	int err;
	unsigned long flags;

	spin_lock_irqsave(&vector_lock, flags);
	err = __assign_irq_vector(irq, data, mask);
	spin_unlock_irqrestore(&vector_lock, flags);
	return err;
}

static int assign_irq_vector_policy(int irq, int node,
				    struct apic_chip_data *data,
				    struct irq_alloc_info *info)
{
	if (info && info->mask)
		return assign_irq_vector(irq, data, info->mask);
	if (node != NUMA_NO_NODE &&
	    assign_irq_vector(irq, data, cpumask_of_node(node)) == 0)
		return 0;
	return assign_irq_vector(irq, data, apic->target_cpus());
}

static struct irq_chip lapic_controller = {
};

static void x86_vector_free_irqs(struct irq_domain *domain,
				 unsigned int virq, unsigned int nr_irqs)
{
	struct apic_chip_data *apic_data;
	struct irq_data *irq_data;
	unsigned long flags;
	int i;

	for (i = 0; i < nr_irqs; i++) {
		irq_data = irq_domain_get_irq_data(&x86_vector_domain, virq + i);
		if (irq_data && irq_data->chip_data) {
			spin_lock_irqsave(&vector_lock, flags);
			clear_irq_vector(virq + i, irq_data->chip_data);
			apic_data = irq_data->chip_data;
			irq_domain_reset_irq_data(irq_data);
			spin_unlock_irqrestore(&vector_lock, flags);

			kfree(apic_data);

			if (virq + i < nr_legacy_irqs()) {
				memset(&legacy_irq_data[virq + i], 0,
					sizeof(struct apic_chip_data));
			}
		}
	}
}

static int x86_vector_alloc_irqs(struct irq_domain *domain, unsigned int virq,
				 unsigned int nr_irqs, void *arg)
{
	struct irq_alloc_info *info = arg;
	struct apic_chip_data *chip_data;
	struct irq_data *irq_data;
	int i, ret, node;

	for (i = 0; i < nr_irqs; i++) {
		irq_data = irq_domain_get_irq_data(domain, virq + i);
		BUG_ON(!irq_data);
		node = irq_data_get_node(irq_data);

		if (virq + i < nr_legacy_irqs())
			chip_data = &legacy_irq_data[virq + i];
		else
			chip_data = kzalloc_node(sizeof(*chip_data), GFP_KERNEL, node);

		if (!chip_data) {
			ret = -ENOMEM;
			goto error;
		}

		irq_data->chip = &lapic_controller;
		irq_data->chip_data = chip_data;
		irq_data->hwirq = virq + i;

		ret = assign_irq_vector_policy(virq + i, node, chip_data, info);
		if (ret)
			goto error;
	}

	return 0;

error:
	x86_vector_free_irqs(domain, virq, i + 1);
	return ret;
}

static const struct irq_domain_ops x86_vector_domain_ops = {
	.alloc	= x86_vector_alloc_irqs,
	.free	= x86_vector_free_irqs,
};

struct irq_domain x86_vector_domain = {
	.name	= "x86-vector",
	.ops	= &x86_vector_domain_ops,
};

/*
 * This functin link or allocate data structures used
 * by APIC and IO-APIC.
 *
 * This function does NOT enable APIC or IO-APIC!
 *
 * Note that all APIC and IO-APIC information were filled
 * early by paring the ACPI tables in setup_arch().
 */
void __init x86_apic_ioapic_init(void)
{
	int i;

	for (i = 0; i < nr_legacy_irqs(); i++) {
		struct apic_chip_data *data;

		data = &legacy_irq_data[i];
		data->cfg.vector = ISA_IRQ_VECTOR(i);
		cpumask_setall(data->domain);

		/*
		 * The irq chip and handler will be set later
		 * by init_ISA_irqs()
		 */
		irq_set_chip_data(i, data);
	}

	irq_set_default_host(&x86_vector_domain);

	arch_ioapic_init();
}
