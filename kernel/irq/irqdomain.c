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
#include <lego/irqdomain.h>
#include <lego/kernel.h>
#include <lego/cpumask.h>

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
	int virq, ret;

	if (unlikely(!domain)) {
		WARN(1, "domain is NULL, can not allocate IRQ\n");
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

	/*
	 * Domain chip's callback
	 * It will allocate irq_data->chip_data and
	 * do other necessary chip specific settings:
	 */
	ret = domain->ops->alloc(domain, virq, nr_irqs, arg);
	if (ret < 0)
		goto err;

	/* TODO: insert into some irq mapping map */

	return virq;

err:
	__irq_number_free(virq, nr_irqs);
	return ret;
}
