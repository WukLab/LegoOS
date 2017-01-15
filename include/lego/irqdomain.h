/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_IRQDOMAIN_H_
#define _LEGO_IRQDOMAIN_H_

#include <lego/types.h>

struct irq_data;

struct irq_domain_ops {
	int (*alloc)(unsigned int virq, unsigned int nr_irqs, void *arg);
	void (*free)(unsigned int virq, unsigned int nr_irqs);
	void (*activate)(struct irq_data *irq_data);
	void (*deactivate)( struct irq_data *irq_data);
};

enum ioapic_domain_type {
	IOAPIC_DOMAIN_INVALID,
	IOAPIC_DOMAIN_LEGACY,
	IOAPIC_DOMAIN_STRICT,
	IOAPIC_DOMAIN_DYNAMIC,
};

/**
 * struct irq_domain - Hardware interrupt number translation object
 * @name: Name of interrupt domain
 * @ops: pointer to irq_domain methods
 * @host_data: private data pointer for use by owner.  Not touched by irq_domain
 *             core code.
 */
struct irq_domain {
	const char *name;
	const struct irq_domain_ops *ops;
	void *host_data;
	unsigned int flags;

	irq_hw_number_t hwirq_max;
};

unsigned int irq_find_mapping(struct irq_domain *host, irq_hw_number_t hwirq);

#endif /* _LEGO_IRQDOMAIN_H_ */
