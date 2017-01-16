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
#include <lego/kernel.h>
#include <lego/cpumask.h>

static struct irq_domain *irq_default_domain;

/**
 * irq_set_default_host() - Set a "default" irq domain
 * @domain: default domain pointer
 *
 * For convenience, it's possible to set a "default" domain that will be used
 * whenever NULL is passed to irq_create_mapping(). It makes life easier for
 * platforms that want to manipulate a few hard coded interrupt numbers that
 * aren't properly represented in the device-tree.
 */
void irq_set_default_host(struct irq_domain *domain)
{
	pr_debug("Default domain set to @0x%p\n", domain);

	irq_default_domain = domain;
}

/**
 * irq_find_mapping() - Find a Lego irq from an hw irq number.
 * @domain: domain owning this hardware interrupt
 * @hwirq: hardware irq number in that domain space
 */
unsigned int irq_find_mapping(struct irq_domain *domain,
			      irq_hw_number_t hwirq)
{
	return 0;
}

int irq_domain_alloc_IRQ_number(int virq, unsigned int cnt, irq_hw_number_t hwirq,
			   int node, const struct cpumask *affinity)
{
	unsigned int hint;

	if (virq >= 0) {
		virq = __irq_number_alloc(virq, virq, cnt, node, affinity);
	} else {
		hint = hwirq % nr_irqs;
		if (hint == 0)
			hint++;
		virq = __irq_number_alloc(-1, hint, cnt, node, affinity);
		if (virq <= 0 && hint > 1) {
			virq = __irq_number_alloc(-1, 1, cnt, node, affinity);
		}
	}

	return virq;
}

static void irq_domain_free_irq_data(unsigned int virq, unsigned int nr_irqs)
{
	struct irq_data *irq_data, *tmp;
	int i;

	for (i = 0; i < nr_irqs; i++) {
		irq_data = irq_get_irq_data(virq + i);
		tmp = irq_data->parent_data;
		irq_data->parent_data = NULL;
		irq_data->domain = NULL;

		while (tmp) {
			irq_data = tmp;
			tmp = tmp->parent_data;
			kfree(irq_data);
		}
	}
}

static struct irq_data *irq_domain_insert_irq_data(struct irq_domain *domain,
						   struct irq_data *child)
{
	struct irq_data *irq_data;

	irq_data = kzalloc_node(sizeof(*irq_data), GFP_KERNEL,
				irq_data_get_node(child));
	if (irq_data) {
		child->parent_data = irq_data;
		irq_data->irq = child->irq;
		irq_data->common = child->common;
		irq_data->domain = domain;
	}

	return irq_data;
}

static int irq_domain_alloc_irq_data(struct irq_domain *domain,
				     unsigned int virq, unsigned int nr_irqs)
{
	struct irq_data *irq_data;
	struct irq_domain *parent;
	int i;

	/* The outermost irq_data is embedded in struct irq_desc */
	for (i = 0; i < nr_irqs; i++) {
		irq_data = irq_get_irq_data(virq + i);
		irq_data->domain = domain;

		for (parent = domain->parent; parent; parent = parent->parent) {
			irq_data = irq_domain_insert_irq_data(parent, irq_data);
			if (!irq_data) {
				irq_domain_free_irq_data(virq, i + 1);
				return -ENOMEM;
			}
		}
	}

	return 0;
}

/**
 * __irq_domain_alloc_irqs - Allocate IRQs from domain
 * @domain:	domain to allocate from
 * @irq_base:	allocate specified IRQ nubmer if irq_base >= 0
 * @nr_irqs:	number of IRQs to allocate
 * @node:	NUMA node id for memory allocation
 * @arg:	domain specific argument
 * @realloc:	IRQ descriptors have already been allocated if true
 * @affinity:	Optional irq affinity mask for multiqueue devices
 *
 * Allocate IRQ numbers and initialized all data structures to support
 * hierarchy IRQ domains.
 * Parameter @realloc is mainly to support legacy IRQs.
 * Returns error code or allocated IRQ number
 *
 * The whole process to setup an IRQ has been split into two steps.
 * The first step, __irq_domain_alloc_irqs(), is to allocate IRQ
 * descriptor and required hardware resources. The second step,
 * irq_domain_activate_irq(), is to program hardwares with preallocated
 * resources. In this way, it's easier to rollback when failing to
 * allocate resources.
 */
int __irq_domain_alloc_irqs(struct irq_domain *domain, int irq_base,
			    unsigned int nr_irqs, int node, void *arg,
			    bool realloc, const struct cpumask *affinity)
{
	int virq, ret, i;

	if (domain == NULL) {
		domain = irq_default_domain;
		if (WARN(!domain, "domain is NULL; cannot allocate IRQ\n"))
			return -EINVAL;
	}

	if (!domain->ops->alloc) {
		pr_debug("domain->ops->alloc() is NULL\n");
		return -ENOSYS;
	}

	/* Get the virtual, global, unique IRQ number */
	if (realloc && irq_base >= 0) {
		virq = irq_base;
	} else {
		virq = irq_domain_alloc_IRQ_number(irq_base, nr_irqs, 0, node, affinity);
		if (virq < 0) {
			pr_debug("cannot allocate IRQ(base %d, count %d)\n",
				 irq_base, nr_irqs);
			return virq;
		}
	}

	if (irq_domain_alloc_irq_data(domain, virq, nr_irqs)) {
		pr_debug("cannot allocate memory for IRQ%d\n", virq);
		ret = -ENOMEM;
		goto out;
	}

	/*
	 * Domain chip's callback
	 * It will allocate irq_data->chip_data and
	 * do other necessary chip specific settings:
	 */
	ret = domain->ops->alloc(domain, virq, nr_irqs, arg);
	if (ret < 0)
		goto out_free;

	/* TODO: insert into some irq mapping map */
	for (i = 0; i < nr_irqs; i++)
		;

	return virq;

out_free:
	irq_domain_free_irq_data(virq, nr_irqs);
out:
	__irq_number_free(virq, nr_irqs);
	return ret;
}

/**
 * irq_domain_get_irq_data - Get irq_data associated with @virq and @domain
 * @domain:	domain to match
 * @virq:	IRQ number to get irq_data
 */
struct irq_data *irq_domain_get_irq_data(struct irq_domain *domain,
					 unsigned int virq)
{
	struct irq_data *irq_data;

	for (irq_data = irq_get_irq_data(virq); irq_data;
	     irq_data = irq_data->parent_data)
		if (irq_data->domain == domain)
			return irq_data;

	return NULL;
}

int irq_domain_alloc_irqs(struct irq_domain *domain, unsigned int irq_base,
			  unsigned int nr_irqs, void *arg)
{
	return domain->ops->alloc(domain, irq_base, nr_irqs, arg);
}

/**
 * irq_domain_alloc_irqs_parent - Allocate interrupts from parent domain
 * @irq_base:	Base IRQ number
 * @nr_irqs:	Number of IRQs to allocate
 * @arg:	Allocation data (arch/domain specific)
 *
 * Check whether the domain has been setup recursive. If not allocate
 * through the parent domain.
 */
int irq_domain_alloc_irqs_parent(struct irq_domain *domain, unsigned int irq_base,
				 unsigned int nr_irqs, void *arg)
{
	struct irq_domain *parent;

	parent = domain->parent;
	if (parent)
		return irq_domain_alloc_irqs(parent, irq_base, nr_irqs, arg);
	return -ENOSYS;
}

/**
 * irq_domain_reset_irq_data - Clear hwirq, chip and chip_data in @irq_data
 * @irq_data:	The pointer to irq_data
 */
void irq_domain_reset_irq_data(struct irq_data *irq_data)
{
	irq_data->hwirq = 0;
	irq_data->chip = &no_irq_chip;
	irq_data->chip_data = NULL;
}

/**
 * irq_domain_activate_irq - Call domain_ops->activate recursively to activate
 *			     interrupt
 * @irq_data:	outermost irq_data associated with interrupt
 *
 * This is the second step to call domain_ops->activate to program interrupt
 * controllers, so the interrupt could actually get delivered.
 */
void irq_domain_activate_irq(struct irq_data *irq_data)
{
	if (irq_data && irq_data->domain) {
		struct irq_domain *domain = irq_data->domain;

		if (irq_data->parent_data)
			irq_domain_activate_irq(irq_data->parent_data);
		if (domain->ops->activate)
			domain->ops->activate(domain, irq_data);
	}
}
