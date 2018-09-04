/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/smp.h>
#include <lego/irq.h>
#include <lego/slab.h>
#include <lego/pci.h>
#include <lego/percpu.h>
#include <lego/irqdesc.h>
#include <lego/irqdomain.h>
#include <lego/spinlock.h>
#include <lego/cpumask.h>

#include <asm/desc.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/numa.h>
#include <asm/i8259.h>
#include <asm/hw_irq.h>
#include <asm/irq_vectors.h>

static struct irq_domain *msi_default_domain;

static void irq_msi_compose_msg(struct irq_data *data, struct msi_msg *msg)
{
	struct irq_cfg *cfg = irqd_cfg(data);

	msg->address_hi = MSI_ADDR_BASE_HI;

	if (x2apic_enabled())
		msg->address_hi |= MSI_ADDR_EXT_DEST_ID(cfg->dest_apicid);

	msg->address_lo =
		MSI_ADDR_BASE_LO |
		((apic->irq_dest_mode == 0) ?
			MSI_ADDR_DEST_MODE_PHYSICAL :
			MSI_ADDR_DEST_MODE_LOGICAL) |
		((apic->irq_delivery_mode != dest_LowestPrio) ?
			MSI_ADDR_REDIRECTION_CPU :
			MSI_ADDR_REDIRECTION_LOWPRI) |
		MSI_ADDR_DEST_ID(cfg->dest_apicid);

	msg->data =
		MSI_DATA_TRIGGER_EDGE |
		MSI_DATA_LEVEL_ASSERT |
		((apic->irq_delivery_mode != dest_LowestPrio) ?
			MSI_DATA_DELIVERY_FIXED :
			MSI_DATA_DELIVERY_LOWPRI) |
		MSI_DATA_VECTOR(cfg->vector);
}

/*
 * IRQ Chip for MSI PCI/PCI-X/PCI-Express Devices,
 * which implement the MSI or MSI-X Capability Structure.
 */
static struct irq_chip pci_msi_controller = {
	.name			= "PCI-MSI",
	.irq_unmask		= pci_msi_unmask_irq,
	.irq_mask		= pci_msi_mask_irq,
	.irq_ack		= irq_chip_ack_parent,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.irq_compose_msi_msg	= irq_msi_compose_msg,
	.flags			= IRQCHIP_SKIP_SET_WAKE,
};

static irq_hw_number_t pci_msi_get_hwirq(struct msi_domain_info *info,
					 msi_alloc_info_t *arg)
{
	return arg->msi_hwirq;
}

static int pci_msi_prepare(struct irq_domain *domain, struct device *dev,
			   int nvec, msi_alloc_info_t *arg)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct msi_desc *desc = first_pci_msi_entry(pdev);

	init_irq_alloc_info(arg, NULL);
	arg->msi_dev = pdev;
	if (desc->msi_attrib.is_msix) {
		arg->type = X86_IRQ_ALLOC_TYPE_MSIX;
	} else {
		arg->type = X86_IRQ_ALLOC_TYPE_MSI;
		arg->flags |= X86_IRQ_ALLOC_CONTIGUOUS_VECTORS;
	}

	return 0;
}

static void pci_msi_set_desc(msi_alloc_info_t *arg, struct msi_desc *desc)
{
	arg->msi_hwirq = pci_msi_domain_calc_hwirq(arg->msi_dev, desc);
}

static struct msi_domain_ops pci_msi_domain_ops = {
	.get_hwirq	= pci_msi_get_hwirq,
	.msi_prepare	= pci_msi_prepare,
	.set_desc	= pci_msi_set_desc,
};

static struct msi_domain_info pci_msi_domain_info = {
	.flags		= MSI_FLAG_USE_DEF_DOM_OPS | MSI_FLAG_USE_DEF_CHIP_OPS |
			  MSI_FLAG_PCI_MSIX,
	.ops		= &pci_msi_domain_ops,
	.chip		= &pci_msi_controller,
	.handler	= handle_edge_irq,
	.handler_name	= "edge",
};

void arch_init_msi_domain(struct irq_domain *parent)
{
	msi_default_domain = pci_msi_create_irq_domain(NULL,
					&pci_msi_domain_info, parent);
	if (!msi_default_domain)
		pr_warn("failed to initialize irqdomain for MSI/MSI-x.\n");
	set_irq_domain_name(msi_default_domain, "x86_msi");
}

/**
 * irq_remapping_get_irq_domain - Get the irqdomain serving the request @info
 * @info: interrupt allocation information, used to identify the IOMMU device
 *
 * There will be one PCI MSI/MSIX irqdomain associated with each interrupt
 * remapping device, so this interface is used to retrieve the PCI MSI/MSIX
 * irqdomain serving request @info.
 * Returns pointer to IRQ domain, or NULL on failure.
 */
/*
 * TODO: IOMMU related stuff
 */
struct irq_domain *
irq_remapping_get_irq_domain(struct irq_alloc_info *info)
{
	return NULL;
}

int native_setup_msi_irqs(struct pci_dev *dev, int nvec, int type)
{
	struct irq_domain *domain;
	struct irq_alloc_info info;

	init_irq_alloc_info(&info, NULL);
	info.type = X86_IRQ_ALLOC_TYPE_MSI;
	info.msi_dev = dev;

	domain = irq_remapping_get_irq_domain(&info);
	if (domain == NULL)
		domain = msi_default_domain;
	if (domain == NULL)
		return -ENOSYS;

	return pci_msi_domain_alloc_irqs(domain, dev, nvec, type);
}

void native_teardown_msi_irq(unsigned int irq)
{
	WARN_ONCE(1, "Not finished!");
}

/*
 * This is the arch setup callback, when you try to
 * enable msix on a pci device.
 */
struct x86_msi_ops x86_msi = {
	.setup_msi_irqs		= native_setup_msi_irqs,
	.teardown_msi_irq	= native_teardown_msi_irq,
};
