/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/irq.h>
#include <lego/irqdesc.h>
#include <lego/spinlock.h>

#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/numa.h>
#include <asm/i8259.h>
#include <asm/hw_irq.h>
#include <asm/irq_vectors.h>

struct apic_chip_data {
	struct irq_cfg		cfg;
	cpumask_var_t		domain;
	u8			move_in_progress : 1;
};

static struct irq_chip lapic_controller;
static DEFINE_SPINLOCK(vector_lock);
static cpumask_var_t vector_cpumask, vector_searchmask, searched_cpumask;

#ifdef CONFIG_X86_IO_APIC
static struct apic_chip_data legacy_irq_data[NR_IRQS_LEGACY];
#endif

static inline struct apic_chip_data *
apic_chip_data(struct irq_data *irq_data)
{
	if (!irq_data)
		return NULL;
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
	irqd_cfg(irq_get_irq_data(irq));
}

void __init arch_irq_init(void)
{
	int i;

	for (i = 0; i < nr_legacy_irqs(); i++) {
		struct apic_chip_data *data;

		data = &legacy_irq_data[i];
		data->cfg.vector = ISA_IRQ_VECTOR(i);
		cpumask_setall(data->domain);
		irq_set_chip_data(i, data);
	}

	arch_ioapic_init();
}
