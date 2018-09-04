/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_IRQDOMAIN_H_
#define _LEGO_IRQDOMAIN_H_

#include <lego/types.h>
#include <lego/radixtree.h>

/* Irq domain flags */
enum {
	/* Irq domain is hierarchical */
	IRQ_DOMAIN_FLAG_HIERARCHY	= (1 << 0),

	/* Core calls alloc/free recursive through the domain hierarchy. */
	IRQ_DOMAIN_FLAG_AUTO_RECURSIVE	= (1 << 1),

	/*
	 * Flags starting from IRQ_DOMAIN_FLAG_NONCORE are reserved
	 * for implementation specific purposes and ignored by the
	 * core code.
	 */
	IRQ_DOMAIN_FLAG_NONCORE		= (1 << 16),
};

/*
 * Should several domains have the same device node, but serve
 * different purposes (for example one domain is for PCI/MSI, and the
 * other for wired IRQs), they can be distinguished using a
 * bus-specific token. Most domains are expected to only carry
 * DOMAIN_BUS_ANY.
 */
enum irq_domain_bus_token {
	DOMAIN_BUS_ANY		= 0,
	DOMAIN_BUS_PCI_MSI,
	DOMAIN_BUS_PLATFORM_MSI,
	DOMAIN_BUS_NEXUS,
};

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
 * @link: Element in global irq_domain list.
 * @name: Name of interrupt domain
 * @ops: pointer to irq_domain methods
 * @host_data: private data pointer for use by owner.  Not touched by irq_domain
 *             core code.
 * @flags: host per irq_domain flags
 *
 * Optional elements
 * @of_node: Pointer to device tree nodes associated with the irq_domain. Used
 *           when decoding device tree interrupt specifiers.
 * @gc: Pointer to a list of generic chips. There is a helper function for
 *      setting up one or more generic chips for interrupt controllers
 *      drivers using the generic chip library which uses this pointer.
 * @parent: Pointer to parent irq_domain to support hierarchy irq_domains
 *
 * Revmap data, used internally by irq_domain
 * @revmap_direct_max_irq: The largest hwirq that can be set for controllers that
 *                         support direct mapping
 * @revmap_size: Size of the linear map table @linear_revmap[]
 * @revmap_tree: Radix map tree for hwirqs that don't fit in the linear map
 * @linear_revmap: Linear table of hwirq->virq reverse mappings
 */
#define IRQ_DOMAIN_NAME_LEN		(32)
struct irq_domain {
	struct list_head		link;
	char				name[IRQ_DOMAIN_NAME_LEN];
	struct irq_domain		*parent;
	const struct irq_domain_ops	*ops;
	void				*host_data;
	unsigned int			flags;

	/* Reverse map data */
	irq_hw_number_t			hwirq_max;
	unsigned int			revmap_direct_max_irq;
	unsigned int			revmap_size;
	struct radix_tree_root		revmap_tree;
	unsigned int			linear_revmap[];
};

static inline void set_irq_domain_name(struct irq_domain *domain, const char *new)
{
	strncpy(domain->name, new, IRQ_DOMAIN_NAME_LEN);
}

unsigned int irq_find_mapping(struct irq_domain *host, irq_hw_number_t hwirq);

int __irq_domain_alloc_irqs(struct irq_domain *domain, int irq_base,
			   unsigned int nr_irqs, int node, void *arg,
			   bool realloc);

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
extern void irq_domain_deactivate_irq(struct irq_data *irq_data);

struct irq_chip;
int irq_domain_set_hwirq_and_chip(struct irq_domain *domain, unsigned int virq,
				  irq_hw_number_t hwirq, struct irq_chip *chip,
				  void *chip_data);

extern struct irq_domain *irq_domain_create_hierarchy(struct irq_domain *parent,
			unsigned int flags, unsigned int size,
			void *fwnode,
			const struct irq_domain_ops *ops, void *host_data);

void irq_domain_free_irqs_top(struct irq_domain *domain, unsigned int virq,
			      unsigned int nr_irqs);

struct irq_domain *__irq_domain_add(void *fwnode, int size,
				    irq_hw_number_t hwirq_max, int direct_max,
				    const struct irq_domain_ops *ops,
				    void *host_data);

/**
 * irq_domain_add_linear() - Allocate and register a linear revmap irq_domain.
 * @of_node: pointer to interrupt controller's device tree node.
 * @size: Number of interrupts in the domain.
 * @ops: map/unmap domain callbacks
 * @host_data: Controller private data pointer
 */
static inline struct irq_domain *irq_domain_add_linear(void *of_node,
					 unsigned int size,
					 const struct irq_domain_ops *ops,
					 void *host_data)
{
	return __irq_domain_add(NULL, size, size, 0, ops, host_data);
}

static inline struct irq_domain *irq_domain_add_tree(void *of_node,
					 const struct irq_domain_ops *ops,
					 void *host_data)
{
	return __irq_domain_add(NULL, 0, ~0, 0, ops, host_data);
}

static inline struct irq_domain *irq_domain_create_linear(void *fwnode,
					 unsigned int size,
					 const struct irq_domain_ops *ops,
					 void *host_data)
{
	return __irq_domain_add(NULL, size, size, 0, ops, host_data);
}

static inline struct irq_domain *irq_domain_create_tree(void *fwnode,
					 const struct irq_domain_ops *ops,
					 void *host_data)
{
	return __irq_domain_add(NULL, 0, ~0, 0, ops, host_data);
}

void dump_irq_domain_list(void);

#endif /* _LEGO_IRQDOMAIN_H_ */
