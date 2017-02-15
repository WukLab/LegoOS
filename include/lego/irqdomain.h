/*
 * Copyright (c) 2016-2017 Wuklab, Purdue University. All rights reserved.
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
struct irq_domain;

struct irq_domain_ops {
	int (*alloc)(struct irq_domain *d, unsigned int virq,
		     unsigned int nr_irqs, void *arg);
	void (*free)(struct irq_domain *d, unsigned int virq,
		     unsigned int nr_irqs);
	void (*activate)(struct irq_domain *d, struct irq_data *irq_data);
	void (*deactivate)(struct irq_domain *d, struct irq_data *irq_data);
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
	const char			*name;
	struct irq_domain		*parent;
	const struct irq_domain_ops	*ops;
	void				*host_data;
	unsigned int			flags;

	/* Reverse map data */
	irq_hw_number_t			hwirq_max;
	unsigned int			revmap_size;
	unsigned int			*linear_revmap;
};

unsigned int irq_find_mapping(struct irq_domain *host, irq_hw_number_t hwirq);

int __irq_domain_alloc_irqs(struct irq_domain *domain, int irq_base,
			   unsigned int nr_irqs, int node, void *arg,
			   bool realloc, const struct cpumask *affinity);

int irq_domain_alloc_IRQ_number(int virq, unsigned int cnt, irq_hw_number_t hwirq,
			   int node, const struct cpumask *affinity);

void irq_set_default_host(struct irq_domain *domain);

extern struct irq_data *irq_domain_get_irq_data(struct irq_domain *domain,
						unsigned int virq);

extern int irq_domain_alloc_irqs_parent(struct irq_domain *domain,
					unsigned int irq_base,
					unsigned int nr_irqs, void *arg);

extern void irq_domain_reset_irq_data(struct irq_data *irq_data);

extern void irq_domain_activate_irq(struct irq_data *irq_data);

#endif /* _LEGO_IRQDOMAIN_H_ */
