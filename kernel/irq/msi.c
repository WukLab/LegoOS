/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/msi.h>
#include <lego/pci.h>
#include <lego/slab.h>
#include <lego/list.h>
#include <lego/delay.h>
#include <lego/timer.h>
#include <lego/kernel.h>
#include <lego/irqdesc.h>
#include <lego/resource.h>
#include <lego/dma-mapping.h>
#include <lego/irqdomain.h>

static int msi_domain_ops_init(struct irq_domain *domain,
			       struct msi_domain_info *info,
			       unsigned int virq, irq_hw_number_t hwirq,
			       msi_alloc_info_t *arg)
{
	irq_domain_set_hwirq_and_chip(domain, virq, hwirq, info->chip,
				      info->chip_data);
	if (info->handler && info->handler_name) {
		__irq_set_handler(virq, info->handler, 0, info->handler_name);
		if (info->handler_data)
			irq_set_handler_data(virq, info->handler_data);
	}
	return 0;
}

static int msi_domain_ops_check(struct irq_domain *domain,
				struct msi_domain_info *info,
				struct device *dev)
{
	return 0;
}

#define msi_domain_ops_get_hwirq	NULL
#define msi_domain_ops_prepare		NULL
#define msi_domain_ops_set_desc		NULL

static struct msi_domain_ops msi_domain_ops_default = {
	.get_hwirq	= msi_domain_ops_get_hwirq,
	.msi_init	= msi_domain_ops_init,
	.msi_check	= msi_domain_ops_check,
	.msi_prepare	= msi_domain_ops_prepare,
	.set_desc	= msi_domain_ops_set_desc,
};

static void msi_domain_update_dom_ops(struct msi_domain_info *info)
{
	struct msi_domain_ops *ops = info->ops;

	if (ops == NULL) {
		info->ops = &msi_domain_ops_default;
		return;
	}

	if (ops->get_hwirq == NULL)
		ops->get_hwirq = msi_domain_ops_default.get_hwirq;
	if (ops->msi_init == NULL)
		ops->msi_init = msi_domain_ops_default.msi_init;
	if (ops->msi_check == NULL)
		ops->msi_check = msi_domain_ops_default.msi_check;
	if (ops->msi_prepare == NULL)
		ops->msi_prepare = msi_domain_ops_default.msi_prepare;
	if (ops->set_desc == NULL)
		ops->set_desc = msi_domain_ops_default.set_desc;
}

static inline void irq_chip_write_msi_msg(struct irq_data *data,
					  struct msi_msg *msg)
{
	data->chip->irq_write_msi_msg(data, msg);
}

static void msi_domain_activate(struct irq_domain *domain,
				struct irq_data *irq_data)
{
	struct msi_msg msg;

	BUG_ON(irq_chip_compose_msi_msg(irq_data, &msg));
	irq_chip_write_msi_msg(irq_data, &msg);
}

static void msi_domain_deactivate(struct irq_domain *domain,
				  struct irq_data *irq_data)
{
	struct msi_msg msg;

	memset(&msg, 0, sizeof(msg));
	irq_chip_write_msi_msg(irq_data, &msg);
}

/**
 * msi_domain_set_affinity - Generic affinity setter function for MSI domains
 * @irq_data:	The irq data associated to the interrupt
 * @mask:	The affinity mask to set
 * @force:	Flag to enforce setting (disable online checks)
 *
 * Intended to be used by MSI interrupt controllers which are
 * implemented with hierarchical domains.
 */
int msi_domain_set_affinity(struct irq_data *irq_data,
			    const struct cpumask *mask, bool force)
{
	struct irq_data *parent = irq_data->parent_data;
	struct msi_msg msg;
	int ret;

	ret = parent->chip->irq_set_affinity(parent, mask, force);
	if (ret >= 0 && ret != IRQ_SET_MASK_OK_DONE) {
		BUG_ON(irq_chip_compose_msi_msg(irq_data, &msg));
		irq_chip_write_msi_msg(irq_data, &msg);
	}

	return ret;
}

static void msi_domain_update_chip_ops(struct msi_domain_info *info)
{
	struct irq_chip *chip = info->chip;

	BUG_ON(!chip || !chip->irq_mask || !chip->irq_unmask);
	if (!chip->irq_set_affinity)
		chip->irq_set_affinity = msi_domain_set_affinity;
}

static int msi_domain_alloc(struct irq_domain *domain, unsigned int virq,
			    unsigned int nr_irqs, void *arg)
{
	struct msi_domain_info *info = domain->host_data;
	struct msi_domain_ops *ops = info->ops;
	irq_hw_number_t hwirq = ops->get_hwirq(info, arg);
	int i, ret;

	if (irq_find_mapping(domain, hwirq) > 0)
		return -EEXIST;

	ret = irq_domain_alloc_irqs_parent(domain, virq, nr_irqs, arg);
	if (ret < 0)
		return ret;

	for (i = 0; i < nr_irqs; i++) {
		ret = ops->msi_init(domain, info, virq + i, hwirq + i, arg);
		if (ret < 0) {
			if (ops->msi_free) {
				for (i--; i > 0; i--)
					ops->msi_free(domain, info, virq + i);
			}
			irq_domain_free_irqs_top(domain, virq, nr_irqs);
			return ret;
		}
	}

	return 0;
}

static void msi_domain_free(struct irq_domain *domain, unsigned int virq,
			    unsigned int nr_irqs)
{
	struct msi_domain_info *info = domain->host_data;
	int i;

	if (info->ops->msi_free) {
		for (i = 0; i < nr_irqs; i++)
			info->ops->msi_free(domain, info, virq + i);
	}
	irq_domain_free_irqs_top(domain, virq, nr_irqs);
}

static const struct irq_domain_ops msi_domain_ops = {
	.alloc		= msi_domain_alloc,
	.free		= msi_domain_free,
	.activate	= msi_domain_activate,
	.deactivate	= msi_domain_deactivate,
};

/**
 * msi_create_irq_domain - Create a MSI interrupt domain
 * @fwnode:	Optional fwnode of the interrupt controller
 * @info:	MSI domain info
 * @parent:	Parent irq domain
 */
struct irq_domain *msi_create_irq_domain(void *fwnode,
					 struct msi_domain_info *info,
					 struct irq_domain *parent)
{
	if (info->flags & MSI_FLAG_USE_DEF_DOM_OPS)
		msi_domain_update_dom_ops(info);
	if (info->flags & MSI_FLAG_USE_DEF_CHIP_OPS)
		msi_domain_update_chip_ops(info);

	return irq_domain_create_hierarchy(parent, 0, 0, fwnode,
					   &msi_domain_ops, info);
}

/**
 * msi_domain_alloc_irqs - Allocate interrupts from a MSI interrupt domain
 * @domain:	The domain to allocate from
 * @dev:	Pointer to device struct of the device for which the interrupts
 *		are allocated
 * @nvec:	The number of interrupts to allocate
 *
 * Returns 0 on success or an error code.
 */
int msi_domain_alloc_irqs(struct irq_domain *domain, struct device *dev,
			  int nvec)
{
	struct msi_domain_info *info = domain->host_data;
	struct msi_domain_ops *ops = info->ops;
	msi_alloc_info_t arg;
	struct msi_desc *desc;
	int i, ret, virq;
	struct pci_dev *pdev = to_pci_dev(dev);

	ret = ops->msi_check(domain, info, dev);
	if (ret == 0)
		ret = ops->msi_prepare(domain, dev, nvec, &arg);
	if (ret)
		return ret;

	for_each_msi_entry(desc, pdev) {
		ops->set_desc(&arg, desc);

		virq = __irq_domain_alloc_irqs(domain, -1, desc->nvec_used,
					       dev_to_node(dev), &arg, false);
		if (virq < 0) {
			ret = -ENOSPC;
			if (ops->handle_error)
				ret = ops->handle_error(domain, desc, ret);
			if (ops->msi_finish)
				ops->msi_finish(&arg, ret);
			return ret;
		}

		for (i = 0; i < desc->nvec_used; i++)
			irq_set_msi_desc_off(virq, i, desc);
	}

	if (ops->msi_finish)
		ops->msi_finish(&arg, 0);

	for_each_msi_entry(desc, pdev) {
		virq = desc->irq;
		if (desc->nvec_used == 1)
			pr_info("(dev %s) irq %d for MSI\n",
				dev_name(dev), virq);
		else
			pr_info("(dev %s) irq [%d-%d] for MSI\n",
				dev_name(dev), virq, virq + desc->nvec_used - 1);
		/*
		 * This flag is set by the PCI layer as we need to activate
		 * the MSI entries before the PCI layer enables MSI in the
		 * card. Otherwise the card latches a random msi message.
		 */
		if (info->flags & MSI_FLAG_ACTIVATE_EARLY) {
			struct irq_data *irq_data;

			irq_data = irq_domain_get_irq_data(domain, desc->irq);
			irq_domain_activate_irq(irq_data);
		}
	}

	return 0;
}
