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
#include <lego/bitmap.h>
#include <lego/irqdesc.h>
#include <lego/cpumask.h>
#include <lego/nodemask.h>
#include <lego/spinlock.h>

cpumask_var_t irq_default_affinity;

int nr_irqs = NR_IRQS;

static DECLARE_BITMAP(allocated_irqs, NR_IRQS);
static DEFINE_SPINLOCK(allocated_irqs_lock);

void irq_mark_irq(unsigned int irq)
{
	spin_lock(&allocated_irqs_lock);
	bitmap_set(allocated_irqs, irq, 1);
	spin_unlock(&allocated_irqs_lock);
}

struct irq_desc irq_desc[NR_IRQS] __cacheline_aligned = {
	[0 ... NR_IRQS-1] = {
		.handle_irq	= handle_bad_irq,
		.depth		= 1,
		.lock		= __SPIN_LOCK_UNLOCKED(irq_desc->lock),
	}
};

static void __init init_irq_default_affinity(void)
{
	if (cpumask_empty(irq_default_affinity))
		cpumask_setall(irq_default_affinity);
}

static void desc_smp_init(struct irq_desc *desc, int node,
			  const struct cpumask *affinity)
{
	if (!affinity)
		affinity = irq_default_affinity;
	cpumask_copy(&desc->irq_common_data.affinity, affinity);

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
	int i, node = first_online_node;

	init_irq_default_affinity();

	pr_info("NR_IRQS:%d\n", NR_IRQS);

	for (i = 0; i < NR_IRQS; i++) {
		spin_lock_init(&irq_desc[i].lock);
		desc_set_defaults(i, &irq_desc[i], node, NULL);
	}

	arch_irq_init();
}

/**
 *	synchronize_irq - wait for pending IRQ handlers (on other CPUs)
 *	@irq: interrupt number to wait for
 *
 *	This function waits for any pending IRQ handlers for this interrupt
 *	to complete before returning. If you use this function while
 *	holding a resource the IRQ handler may need you will deadlock.
 *
 *	This function may be called - with care - from IRQ context.
 */
void synchronize_irq(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (desc) {
	}
}

void __disable_irq(struct irq_desc *desc)
{
	if (!desc->depth++)
		irq_disable(desc);
}

/**
 *	disable_irq_nosync - disable an irq without waiting
 *	@irq: Interrupt to disable
 *
 *	Disable the selected interrupt line.
 *	Disables and Enables are nested.
 *
 *	Unlike disable_irq(), this function does not ensure existing
 *	instances of the IRQ handler have completed before returning.
 *
 *	This function may be called from IRQ context.
 */
void disable_irq_nosync(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc)
		return;
	__disable_irq(desc);
}

/**
 *	disable_irq - disable an irq and wait for completion
 *	@irq: Interrupt to disable
 *
 *	Disable the selected interrupt line.
 *	Disables and Enables are nested.
 *
 *	This function waits for any pending IRQ handlers for this interrupt
 *	to complete before returning. If you use this function while
 *	holding a resource the IRQ handler may need you will deadlock.
 *
 *	This function may be called - with care - from IRQ context.
 */
void disable_irq(unsigned int irq)
{
	disable_irq_nosync(irq);
	synchronize_irq(irq);
}

int __irq_set_trigger(struct irq_desc *desc, unsigned long flags)
{
	struct irq_chip *chip = desc->irq_data.chip;
	int ret, unmask = 0;

	if (!chip || !chip->irq_set_type) {
		/*
		 * IRQF_TRIGGER_* but the PIC does not support multiple
		 * flow-types?
		 */
		pr_debug("No set_type function for IRQ %d (%s)\n",
			 irq_desc_get_irq(desc),
			 chip ? (chip->name ? : "unknown") : "unknown");
		return 0;
	}

	if (chip->flags & IRQCHIP_SET_TYPE_MASKED) {
		if (!irqd_irq_masked(&desc->irq_data))
			mask_irq(desc);
		if (!irqd_irq_disabled(&desc->irq_data))
			unmask = 1;
	}

	/* Mask all flags except trigger mode */
	flags &= IRQ_TYPE_SENSE_MASK;
	ret = chip->irq_set_type(&desc->irq_data, flags);

	switch (ret) {
	case IRQ_SET_MASK_OK:
	case IRQ_SET_MASK_OK_DONE:
		irqd_clear(&desc->irq_data, IRQD_TRIGGER_MASK);
		irqd_set(&desc->irq_data, flags);

	case IRQ_SET_MASK_OK_NOCOPY:
		flags = irqd_get_trigger_type(&desc->irq_data);
		irq_settings_set_trigger_mask(desc, flags);
		irqd_clear(&desc->irq_data, IRQD_LEVEL);
		irq_settings_clr_level(desc);
		if (flags & IRQ_TYPE_LEVEL_MASK) {
			irq_settings_set_level(desc);
			irqd_set(&desc->irq_data, IRQD_LEVEL);
		}

		ret = 0;
		break;
	default:
		pr_err("Setting trigger mode %lu for irq %u failed (%pF)\n",
		       flags, irq_desc_get_irq(desc), chip->irq_set_type);
	}
	if (unmask)
		unmask_irq(desc);
	return ret;
}

/*
 * IRQ resend
 *
 * Is called with interrupts disabled and desc->lock held.
 */
void check_irq_resend(struct irq_desc *desc)
{
}
