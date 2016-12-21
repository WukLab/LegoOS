/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/irq.h>
#include <lego/kernel.h>
#include <lego/irqdesc.h>
#include <lego/cpumask.h>
#include <lego/nodemask.h>
#include <lego/spinlock.h>

struct cpumask irq_default_affinity;

int nr_irqs = NR_IRQS;

static DECLARE_BITMAP(allocated_irqs, NR_IRQS);

struct irq_desc irq_desc[NR_IRQS] __cacheline_aligned = {
	[0 ... NR_IRQS-1] = {
		.handle_irq	= handle_bad_irq,
		.depth		= 1,
		.lock		= __SPIN_LOCK_UNLOCKED(irq_desc->lock),
	}
};

static void __init init_irq_default_affinity(void)
{
	if (cpumask_empty(&irq_default_affinity))
		cpumask_setall(&irq_default_affinity);
}

static void desc_smp_init(struct irq_desc *desc, int node,
			  const struct cpumask *affinity)
{
	if (!affinity)
		affinity = &irq_default_affinity;
	cpumask_copy(desc->irq_common_data.affinity, affinity);

#ifdef CONFIG_NUMA
	desc->irq_common_data.node = node;
#endif
}

static void desc_set_defaults(unsigned int irq, struct irq_desc *desc, int node,
			      const struct cpumask *affinity)
{
	desc->irq_common_data.handler_data = NULL;
	desc->irq_common_data.msi_desc = NULL;

	desc->irq_data.common = &desc->irq_common_data;
	desc->irq_data.irq = irq;
	desc->irq_data.chip = &no_irq_chip;
	desc->irq_data.chip_data = NULL;
	desc->handle_irq = handle_bad_irq;
	desc->depth = 1;
	desc->irq_count = 0;
	desc->irqs_unhandled = 0;
	desc->name = NULL;
	desc_smp_init(desc, node, affinity);
}

void __init irq_init(void)
{
	int i, count, node = first_online_node;
	struct irq_desc *desc;

	init_irq_default_affinity();

	pr_info("NR_IRQS:%d\n", NR_IRQS);

	desc = irq_desc;
	count = ARRAY_SIZE(irq_desc);

	for (i = 0; i < count; i++) {
		spin_lock_init(&desc[i].lock);
		desc_set_defaults(i, &desc[i], node, NULL);
	}
}
