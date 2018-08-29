/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/irq.h>
#include <lego/slab.h>
#include <lego/irqdesc.h>
#include <lego/irqchip.h>
#include <lego/irqdomain.h>
#include <lego/kernel.h>
#include <lego/cpumask.h>
#include <lego/mutex.h>

static LIST_HEAD(irq_domain_list);
static DEFINE_MUTEX(irq_domain_mutex);

static DEFINE_MUTEX(revmap_trees_mutex);
static struct irq_domain *irq_default_domain;

void dump_irq_domain_list(void)
{
	unsigned long flags;
	struct irq_desc *desc;
	struct irq_domain *domain;
	struct radix_tree_iter iter;
	void *data, **slot;
	int i;

	pr_info(" %-16s  %-6s  %-10s  %-10s  %s\n",
		   "name", "mapped", "linear-max", "direct-max", "devtree-node");

	mutex_lock(&irq_domain_mutex);
	list_for_each_entry(domain, &irq_domain_list, link) {
		int count = 0;
		radix_tree_for_each_slot(slot, &domain->revmap_tree, &iter, 0)
			count++;
		pr_info("%c%-16s  %6u  %10u  %10u  %s\n",
			   domain == irq_default_domain ? '*' : ' ', domain->name,
			   domain->revmap_size + count, domain->revmap_size,
			   domain->revmap_direct_max_irq, "");
	}
	mutex_unlock(&irq_domain_mutex);

	pr_info("%-5s  %-7s  %-15s  %-*s  %6s  %-14s  %s\n", "irq", "hwirq",
		      "chip name", (int)(2 * sizeof(void *) + 2), "chip data",
		      "active", "type", "domain");

	for (i = 1; i < nr_irqs; i++) {
		desc = irq_to_desc(i);
		if (!desc)
			continue;

		spin_lock_irqsave(&desc->lock, flags);
		domain = desc->irq_data.domain;

		if (domain) {
			struct irq_chip *chip;
			int hwirq = desc->irq_data.hwirq;
			bool direct;

			pr_info("%5d  ", i);
			pr_cont("0x%05x  ", hwirq);

			chip = irq_desc_get_chip(desc);
			pr_cont("%-15s  ", (chip && chip->name) ? chip->name : "none");

			data = irq_desc_get_chip_data(desc);
			if (data)
				pr_cont("0x%p", data);
			else
				pr_cont("  %p  ", data);

			pr_cont("   %c    ", (desc->action && desc->action->handler) ? '*' : ' ');
			direct = (i == hwirq) && (i < domain->revmap_direct_max_irq);
			pr_cont("%6s%-8s  ",
				   (hwirq < domain->revmap_size) ? "LINEAR" : "RADIX",
				   direct ? "(DIRECT)" : "");
			pr_cont("%s\n", desc->irq_data.domain->name);
		}

		spin_unlock_irqrestore(&desc->lock, flags);
	}
}

/**
 * __irq_domain_add() - Allocate a new irq_domain data structure
 * @of_node: optional device-tree node of the interrupt controller
 * @size: Size of linear map; 0 for radix mapping only
 * @hwirq_max: Maximum number of interrupts supported by controller
 * @direct_max: Maximum value of direct maps; Use ~0 for no limit; 0 for no
 *              direct mapping
 * @ops: domain callbacks
 * @host_data: Controller private data pointer
 *
 * Allocates and initialize and irq_domain structure.
 * Returns pointer to IRQ domain, or NULL on failure.
 */
struct irq_domain *__irq_domain_add(void *fwnode, int size,
				    irq_hw_number_t hwirq_max, int direct_max,
				    const struct irq_domain_ops *ops,
				    void *host_data)
{
	struct irq_domain *domain;

	domain = kzalloc(sizeof(*domain) + (sizeof(unsigned int) * size), GFP_KERNEL);
	if (WARN_ON(!domain))
		return NULL;

	/* Fill structure */
	INIT_RADIX_TREE(&domain->revmap_tree, GFP_KERNEL);
	domain->ops = ops;
	domain->host_data = host_data;
	domain->hwirq_max = hwirq_max;
	domain->revmap_size = size;
	domain->revmap_direct_max_irq = direct_max;

	mutex_lock(&irq_domain_mutex);
	list_add(&domain->link, &irq_domain_list);
	mutex_unlock(&irq_domain_mutex);

	return domain;
}

/**
 * irq_domain_create_hierarchy - Add a irqdomain into the hierarchy
 * @parent:	Parent irq domain to associate with the new domain
 * @flags:	Irq domain flags associated to the domain
 * @size:	Size of the domain. See below
 * @fwnode:	Optional fwnode of the interrupt controller
 * @ops:	Pointer to the interrupt domain callbacks
 * @host_data:	Controller private data pointer
 *
 * If @size is 0 a tree domain is created, otherwise a linear domain.
 *
 * If successful the parent is associated to the new domain and the
 * domain flags are set.
 * Returns pointer to IRQ domain, or NULL on failure.
 */
struct irq_domain *irq_domain_create_hierarchy(struct irq_domain *parent,
					    unsigned int flags,
					    unsigned int size,
					    void *fwnode,
					    const struct irq_domain_ops *ops,
					    void *host_data)
{
	struct irq_domain *domain;

	if (size)
		domain = irq_domain_create_linear(fwnode, size, ops, host_data);
	else
		domain = irq_domain_create_tree(fwnode, ops, host_data);
	if (domain) {
		domain->parent = parent;
		domain->flags |= flags;
	}

	return domain;
}

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
	struct irq_data *data;

	/* Look for default domain if nececssary */
	if (domain == NULL)
		domain = irq_default_domain;
	if (domain == NULL)
		return 0;

	if (hwirq < domain->revmap_direct_max_irq) {
		data = irq_domain_get_irq_data(domain, hwirq);
		if (data && data->hwirq == hwirq)
			return hwirq;
	}

	/* Check if the hwirq is in the linear revmap. */
	if (hwirq < domain->revmap_size)
		return domain->linear_revmap[hwirq];

	/*
	 * HACK!!!
	 *
	 * We don't have RCU, so have to use mutex to sync
	 * with concurrent writers. Fortunately, the write
	 * will NOT happen frequently (at least in current codebase).
	 */
	mutex_lock(&revmap_trees_mutex);
	data = radix_tree_lookup(&domain->revmap_tree, hwirq);
	mutex_unlock(&revmap_trees_mutex);
	return data ? data->irq : 0;
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

/**
 * irq_domain_insert_irq
 *
 * Insert virq and its hwirq mapping into domain reverse map.
 * All parent domains are updated as well.
 */
static void irq_domain_insert_irq(int virq)
{
	struct irq_data *data;

	for (data = irq_get_irq_data(virq); data; data = data->parent_data) {
		struct irq_domain *domain = data->domain;
		irq_hw_number_t hwirq = data->hwirq;

		if (hwirq < domain->revmap_size) {
			domain->linear_revmap[hwirq] = virq;
		} else {
			mutex_lock(&revmap_trees_mutex);
			radix_tree_insert(&domain->revmap_tree, hwirq, data);
			mutex_unlock(&revmap_trees_mutex);
		}

		pr_debug("%s: Domain: %s HW-IRQ: %lu IRQ: %d (Mapping: %s)\n",
			__func__, domain->name, hwirq, virq,
			hwirq < domain->revmap_size ? "linear" : "radix");
	}

	irq_clear_status_flags(virq, IRQ_NOREQUEST);
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

static int irq_domain_alloc_descs(int virq, unsigned int cnt,
				  irq_hw_number_t hwirq, int node)
{
	unsigned int hint;

	if (virq >= 0) {
		virq = irq_alloc_descs(virq, virq, cnt, node);
	} else {
		hint = hwirq % nr_irqs;
		if (hint == 0)
			hint++;
		virq = irq_alloc_descs_from(hint, cnt, node);
		if (virq <= 0 && hint > 1)
			virq = irq_alloc_descs_from(1, cnt, node);
	}

	return virq;
}

static bool irq_domain_is_auto_recursive(struct irq_domain *domain)
{
	return domain->flags & IRQ_DOMAIN_FLAG_AUTO_RECURSIVE;
}

static void irq_domain_free_irqs_recursive(struct irq_domain *domain,
					   unsigned int irq_base,
					   unsigned int nr_irqs)
{
	domain->ops->free(domain, irq_base, nr_irqs);
	if (irq_domain_is_auto_recursive(domain)) {
		BUG_ON(!domain->parent);
		irq_domain_free_irqs_recursive(domain->parent, irq_base,
					       nr_irqs);
	}
}

static int irq_domain_alloc_irqs_recursive(struct irq_domain *domain,
					   unsigned int irq_base,
					   unsigned int nr_irqs, void *arg)
{
	int ret = 0;
	struct irq_domain *parent = domain->parent;
	bool recursive = irq_domain_is_auto_recursive(domain);

	BUG_ON(recursive && !parent);
	if (recursive)
		ret = irq_domain_alloc_irqs_recursive(parent, irq_base,
						      nr_irqs, arg);
	if (ret >= 0)
		ret = domain->ops->alloc(domain, irq_base, nr_irqs, arg);
	if (ret < 0 && recursive)
		irq_domain_free_irqs_recursive(parent, irq_base, nr_irqs);

	return ret;
}

/**
 * __irq_domain_alloc_irqs - Allocate IRQs from domain
 * @domain:	domain to allocate from
 * @irq_base:	allocate specified IRQ nubmer if irq_base >= 0
 * @nr_irqs:	number of IRQs to allocate
 * @node:	NUMA node id for memory allocation
 * @arg:	domain specific argument
 * @realloc:	IRQ descriptors have already been allocated if true
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
			    bool realloc)
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
		virq = irq_domain_alloc_descs(irq_base, nr_irqs, 0, node);
		if (virq < 0) {
			pr_debug("cannot allocate IRQ(base %d, count %d)\n",
				 irq_base, nr_irqs);
			return virq;
		}
	}

	if (irq_domain_alloc_irq_data(domain, virq, nr_irqs)) {
		pr_debug("cannot allocate memory for IRQ%d\n", virq);
		ret = -ENOMEM;
		goto out_free_desc;
	}

	/*
	 * Domain chip's callback
	 * It will allocate irq_data->chip_data and
	 * do other necessary chip specific settings:
	 */
	mutex_lock(&irq_domain_mutex);
	ret = irq_domain_alloc_irqs_recursive(domain, virq, nr_irqs, arg);
	if (ret < 0) {
		mutex_unlock(&irq_domain_mutex);
		goto out_free_irq_data;
	}
	for (i = 0; i < nr_irqs; i++)
		irq_domain_insert_irq(virq + i);
	mutex_unlock(&irq_domain_mutex);

	return virq;

out_free_irq_data:
	irq_domain_free_irq_data(virq, nr_irqs);
out_free_desc:
	irq_free_descs(virq, nr_irqs);
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

/**
 * irq_domain_set_hwirq_and_chip - Set hwirq and irqchip of @virq at @domain
 * @domain:	Interrupt domain to match
 * @virq:	IRQ number
 * @hwirq:	The hwirq number
 * @chip:	The associated interrupt chip
 * @chip_data:	The associated chip data
 */
int irq_domain_set_hwirq_and_chip(struct irq_domain *domain, unsigned int virq,
				  irq_hw_number_t hwirq, struct irq_chip *chip,
				  void *chip_data)
{
	struct irq_data *irq_data = irq_domain_get_irq_data(domain, virq);

	if (!irq_data)
		return -ENOENT;

	irq_data->hwirq = hwirq;
	irq_data->chip = chip ? chip : &no_irq_chip;
	irq_data->chip_data = chip_data;

	return 0;
}

/**
 * irq_domain_free_irqs_parent - Free interrupts from parent domain
 * @irq_base:	Base IRQ number
 * @nr_irqs:	Number of IRQs to free
 *
 * Check whether the domain has been setup recursive. If not free
 * through the parent domain.
 */
void irq_domain_free_irqs_parent(struct irq_domain *domain,
				 unsigned int irq_base, unsigned int nr_irqs)
{
	/* irq_domain_free_irqs_recursive() will call parent's free */
	if (!irq_domain_is_auto_recursive(domain) && domain->parent)
		irq_domain_free_irqs_recursive(domain->parent, irq_base,
					       nr_irqs);
}

/**
 * irq_domain_free_irqs_common - Clear irq_data and free the parent
 * @domain:	Interrupt domain to match
 * @virq:	IRQ number to start with
 * @nr_irqs:	The number of irqs to free
 */
void irq_domain_free_irqs_common(struct irq_domain *domain, unsigned int virq,
				 unsigned int nr_irqs)
{
	struct irq_data *irq_data;
	int i;

	for (i = 0; i < nr_irqs; i++) {
		irq_data = irq_domain_get_irq_data(domain, virq + i);
		if (irq_data)
			irq_domain_reset_irq_data(irq_data);
	}
	irq_domain_free_irqs_parent(domain, virq, nr_irqs);
}

/*
 * irq_domain_free_irqs_top - Clear handler and handler data, clear irqdata and free parent
 * @domain:	Interrupt domain to match
 * @virq:	IRQ number to start with
 * @nr_irqs:	The number of irqs to free
 */
void irq_domain_free_irqs_top(struct irq_domain *domain, unsigned int virq,
			      unsigned int nr_irqs)
{
	int i;

	for (i = 0; i < nr_irqs; i++) {
		irq_set_handler_data(virq + i, NULL);
		irq_set_handler(virq + i, NULL);
	}
	irq_domain_free_irqs_common(domain, virq, nr_irqs);
}
