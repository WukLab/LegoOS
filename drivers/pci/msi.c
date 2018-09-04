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

#include <asm/io.h>
#include "pci.h"

static int pci_msi_enable = 1;

struct pci_dev *msi_desc_to_pci_dev(struct msi_desc *desc)
{
	return desc->dev;
}

#define msix_table_size(flags)	((flags & PCI_MSIX_FLAGS_QSIZE) + 1)

#ifndef arch_setup_msi_irqs
# define arch_setup_msi_irqs default_setup_msi_irqs
# define HAVE_DEFAULT_MSI_SETUP_IRQS
#endif

#ifdef HAVE_DEFAULT_MSI_SETUP_IRQS
int default_setup_msi_irqs(struct pci_dev *dev, int nvec, int type)
{
	struct msi_desc *entry;
	int ret;

	/*
	 * If an architecture wants to support multiple MSI, it needs to
	 * override arch_setup_msi_irqs()
	 */
	if (type == PCI_CAP_ID_MSI && nvec > 1)
		return 1;

	list_for_each_entry(entry, &dev->msi_list, list) {
		ret = arch_setup_msi_irq(dev, entry);
		if (ret < 0)
			return ret;
		if (ret > 0)
			return -ENOSPC;
	}

	return 0;
}
#endif

#ifndef arch_teardown_msi_irqs
# define arch_teardown_msi_irqs default_teardown_msi_irqs
# define HAVE_DEFAULT_MSI_TEARDOWN_IRQS
#endif

#ifdef HAVE_DEFAULT_MSI_TEARDOWN_IRQS
void default_teardown_msi_irqs(struct pci_dev *dev)
{
	struct msi_desc *entry;

	list_for_each_entry(entry, &dev->msi_list, list) {
		int i, nvec;
		if (entry->irq == 0)
			continue;
		if (entry->nvec_used)
			nvec = entry->nvec_used;
		else
			nvec = 1 << entry->msi_attrib.multiple;
		for (i = 0; i < nvec; i++)
			arch_teardown_msi_irq(entry->irq + i);
	}
}
#endif

static void pci_intx_for_msi(struct pci_dev *dev, int enable)
{
	if (!(dev->dev_flags & PCI_DEV_FLAGS_MSI_INTX_DISABLE_BUG))
		pci_intx(dev, enable);
}

static void msi_set_enable(struct pci_dev *dev, int enable)
{
	u16 control;

	pci_read_config_word(dev, dev->msi_cap + PCI_MSI_FLAGS, &control);
	control &= ~PCI_MSI_FLAGS_ENABLE;
	if (enable)
		control |= PCI_MSI_FLAGS_ENABLE;
	pci_write_config_word(dev, dev->msi_cap + PCI_MSI_FLAGS, control);
}

static void msix_set_enable(struct pci_dev *dev, int enable)
{
	u16 control;

	pci_read_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, &control);
	control &= ~PCI_MSIX_FLAGS_ENABLE;
	if (enable)
		control |= PCI_MSIX_FLAGS_ENABLE;
	pci_write_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, control);
}

void pci_msi_init_pci_dev(struct pci_dev *dev)
{
	INIT_LIST_HEAD(&dev->msi_list);

	/* Disable the msi hardware to avoid screaming interrupts
	 * during boot.  This is the power on reset default so
	 * usually this should be a noop.
	 */
	dev->msi_cap = pci_find_capability(dev, PCI_CAP_ID_MSI);
	if (dev->msi_cap)
		msi_set_enable(dev, 0);

	dev->msix_cap = pci_find_capability(dev, PCI_CAP_ID_MSIX);
	if (dev->msix_cap)
		msix_set_enable(dev, 0);
}

/*
 * This internal function does not flush PCI writes to the device.
 * All users must ensure that they read from the device before either
 * assuming that the device state is up to date, or returning out of this
 * file.  This saves a few milliseconds when initialising devices with lots
 * of MSI-X interrupts.
 */
static u32 __msix_mask_irq(struct msi_desc *desc, u32 flag)
{
	u32 mask_bits = desc->masked;
	unsigned offset = desc->msi_attrib.entry_nr * PCI_MSIX_ENTRY_SIZE +
						PCI_MSIX_ENTRY_VECTOR_CTRL;
	mask_bits &= ~PCI_MSIX_ENTRY_CTRL_MASKBIT;
	if (flag)
		mask_bits |= PCI_MSIX_ENTRY_CTRL_MASKBIT;
	writel(mask_bits, desc->mask_base + offset);

	return mask_bits;
}

static void msix_mask_irq(struct msi_desc *desc, u32 flag)
{
	desc->masked = __msix_mask_irq(desc, flag);
}

/*
 * PCI 2.3 does not specify mask bits for each MSI interrupt.  Attempting to
 * mask all MSI interrupts by clearing the MSI enable bit does not work
 * reliably as devices without an INTx disable bit will then generate a
 * level IRQ which will never be cleared.
 */
u32 __pci_msi_desc_mask_irq(struct msi_desc *desc, u32 mask, u32 flag)
{
	u32 mask_bits = desc->masked;

	if (!desc->msi_attrib.maskbit)
		return 0;

	mask_bits &= ~mask;
	mask_bits |= flag;
	pci_write_config_dword(msi_desc_to_pci_dev(desc), desc->mask_pos,
			       mask_bits);

	return mask_bits;
}

static void msi_mask_irq(struct msi_desc *desc, u32 mask, u32 flag)
{
	desc->masked = __pci_msi_desc_mask_irq(desc, mask, flag);
}

static void free_msi_irqs(struct pci_dev *dev)
{
	struct msi_desc *entry, *tmp;

	list_for_each_entry(entry, &dev->msi_list, list) {
		int i, nvec;
		if (!entry->irq)
			continue;
		if (entry->nvec_used)
			nvec = entry->nvec_used;
		else
			nvec = 1 << entry->msi_attrib.multiple;

		for (i = 0; i < nvec; i++)
			BUG_ON(irq_has_action(entry->irq + i));
	}

	arch_teardown_msi_irqs(dev);

	list_for_each_entry_safe(entry, tmp, &dev->msi_list, list) {
		if (entry->msi_attrib.is_msix) {
			if (list_is_last(&entry->list, &dev->msi_list))
				iounmap(entry->mask_base);
		}

		list_del(&entry->list);
		kfree(entry);
	}
}

/**
 * pci_msi_check_device - check whether MSI may be enabled on a device
 * @dev: pointer to the pci_dev data structure of MSI device function
 * @nvec: how many MSIs have been requested ?
 * @type: are we checking for MSI or MSI-X ?
 *
 * Look at global flags, the device itself, and its parent busses
 * to determine if MSI/-X are supported for the device. If MSI/-X is
 * supported return 0, else return an error code.
 **/
static int pci_msi_check_device(struct pci_dev *dev, int nvec, int type)
{
	struct pci_bus *bus;

	/* MSI must be globally enabled and supported by the device */
	if (!pci_msi_enable || !dev || dev->no_msi)
		return -EINVAL;

	/*
	 * You can't ask to have 0 or less MSIs configured.
	 *  a) it's stupid ..
	 *  b) the list manipulation code assumes nvec >= 1.
	 */
	if (nvec < 1)
		return -ERANGE;

	/*
	 * Any bridge which does NOT route MSI transactions from its
	 * secondary bus to its primary bus must set NO_MSI flag on
	 * the secondary pci_bus.
	 * We expect only arch-specific PCI host bus controller driver
	 * or quirks for specific PCI bridges to be setting NO_MSI.
	 */
	for (bus = dev->bus; bus; bus = bus->parent)
		if (bus->bus_flags & PCI_BUS_FLAGS_NO_MSI)
			return -EINVAL;

	return 0;
}

/**
 * pci_msix_table_size - return the number of device's MSI-X table entries
 * @dev: pointer to the pci_dev data structure of MSI-X device function
 */
int pci_msix_table_size(struct pci_dev *dev)
{
	u16 control;

	if (!dev->msix_cap)
		return 0;

	pci_read_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, &control);
	return msix_table_size(control);
}

static void __iomem *msix_map_region(struct pci_dev *dev, unsigned nr_entries)
{
	resource_size_t phys_addr;
	u32 table_offset;
	u8 bir;

	pci_read_config_dword(dev, dev->msix_cap + PCI_MSIX_TABLE,
			      &table_offset);
	bir = (u8)(table_offset & PCI_MSIX_TABLE_BIR);
	table_offset &= PCI_MSIX_TABLE_OFFSET;
	phys_addr = pci_resource_start(dev, bir) + table_offset;

	return ioremap_nocache(phys_addr, nr_entries * PCI_MSIX_ENTRY_SIZE);
}

static struct msi_desc *alloc_msi_entry(struct pci_dev *dev)
{
	struct msi_desc *desc = kzalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc)
		return NULL;

	INIT_LIST_HEAD(&desc->list);
	desc->dev = dev;

	return desc;
}

static int msix_setup_entries(struct pci_dev *dev, void __iomem *base,
			      struct msix_entry *entries, int nvec)
{
	struct msi_desc *entry;
	int i;

	for (i = 0; i < nvec; i++) {
		entry = alloc_msi_entry(dev);
		if (!entry) {
			if (!i)
				iounmap(base);
			else
				free_msi_irqs(dev);
			/* No enough memory. Don't try again */
			return -ENOMEM;
		}

		entry->msi_attrib.is_msix	= 1;
		entry->msi_attrib.is_64		= 1;
		entry->msi_attrib.entry_nr	= entries[i].entry;
		entry->msi_attrib.default_irq	= dev->irq;
		entry->msi_attrib.pos		= dev->msix_cap;
		entry->mask_base		= base;
		entry->nvec_used		= 1;

		list_add_tail(&entry->list, &dev->msi_list);
	}

	return 0;
}

static void msix_program_entries(struct pci_dev *dev,
				 struct msix_entry *entries)
{
	struct msi_desc *entry;
	int i = 0;

	list_for_each_entry(entry, &dev->msi_list, list) {
		int offset = entries[i].entry * PCI_MSIX_ENTRY_SIZE +
						PCI_MSIX_ENTRY_VECTOR_CTRL;

		entries[i].vector = entry->irq;
		irq_set_msi_desc(entry->irq, entry);
		entry->masked = readl(entry->mask_base + offset);
		msix_mask_irq(entry, 1);
		i++;
	}
}

/**
 * msix_capability_init - configure device's MSI-X capability
 * @dev: pointer to the pci_dev data structure of MSI-X device function
 * @entries: pointer to an array of struct msix_entry entries
 * @nvec: number of @entries
 *
 * Setup the MSI-X capability structure of device function with a
 * single MSI-X irq. A return of zero indicates the successful setup of
 * requested MSI-X entries with allocated irqs or non-zero for otherwise.
 **/
static int msix_capability_init(struct pci_dev *dev,
				struct msix_entry *entries, int nvec)
{
	int ret;
	u16 control;
	void __iomem *base;

	pci_read_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, &control);

	/* Ensure MSI-X is disabled while it is set up */
	control &= ~PCI_MSIX_FLAGS_ENABLE;
	pci_write_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, control);

	/* Request & Map MSI-X table region */
	base = msix_map_region(dev, msix_table_size(control));
	if (!base)
		return -ENOMEM;

	ret = msix_setup_entries(dev, base, entries, nvec);
	if (ret)
		return ret;

	ret = arch_setup_msi_irqs(dev, nvec, PCI_CAP_ID_MSIX);
	if (ret)
		goto error;

	/*
	 * Some devices require MSI-X to be enabled before we can touch the
	 * MSI-X registers.  We need to mask all the vectors to prevent
	 * interrupts coming in before they're fully set up.
	 */
	control |= PCI_MSIX_FLAGS_MASKALL | PCI_MSIX_FLAGS_ENABLE;
	pci_write_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, control);

	msix_program_entries(dev, entries);

	/* Set MSI-X enabled bits and unmask the function */
	pci_intx_for_msi(dev, 0);
	dev->msix_enabled = 1;

	control &= ~PCI_MSIX_FLAGS_MASKALL;
	pci_write_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, control);

	return 0;

error:
	if (ret < 0) {
		/*
		 * If we had some success, report the number of irqs
		 * we succeeded in setting up.
		 */
		struct msi_desc *entry;
		int avail = 0;

		list_for_each_entry(entry, &dev->msi_list, list) {
			if (entry->irq != 0)
				avail++;
		}
		if (avail != 0)
			ret = avail;
	}

	free_msi_irqs(dev);

	return ret;
}

/**
 * pci_enable_msix - configure device's MSI-X capability structure
 * @dev: pointer to the pci_dev data structure of MSI-X device function
 * @entries: pointer to an array of MSI-X entries
 * @nvec: number of MSI-X irqs requested for allocation by device driver
 *
 * Setup the MSI-X capability structure of device function with the number
 * of requested irqs upon its software driver call to request for
 * MSI-X mode enabled on its hardware device function. A return of zero
 * indicates the successful configuration of MSI-X capability structure
 * with new allocated MSI-X irqs. A return of < 0 indicates a failure.
 * Or a return of > 0 indicates that driver request is exceeding the number
 * of irqs or MSI-X vectors available. Driver should use the returned value to
 * re-send its request.
 **/
int pci_enable_msix(struct pci_dev *dev, struct msix_entry *entries, int nvec)
{
	int status, nr_entries;
	int i, j;

	if (!entries || !dev->msix_cap)
		return -EINVAL;

	status = pci_msi_check_device(dev, nvec, PCI_CAP_ID_MSIX);
	if (status)
		return status;

	nr_entries = pci_msix_table_size(dev);
	if (nvec > nr_entries)
		return nr_entries;

	/* Check for any invalid entries */
	for (i = 0; i < nvec; i++) {
		if (entries[i].entry >= nr_entries)
			return -EINVAL;		/* invalid entry */
		for (j = i + 1; j < nvec; j++) {
			if (entries[i].entry == entries[j].entry)
				return -EINVAL;	/* duplicate entry */
		}
	}
	WARN_ON(!!dev->msix_enabled);

	/* Check whether driver already requested for MSI irq */
	if (dev->msi_enabled) {
		pr_info("(dev %s) can't enable MSI-X "
		       "(MSI IRQ already assigned)\n",
			dev_name(&dev->dev));
		return -EINVAL;
	}
	status = msix_capability_init(dev, entries, nvec);
	return status;
}

/**
 * pci_enable_msix_range - configure device's MSI-X capability structure
 * @dev: pointer to the pci_dev data structure of MSI-X device function
 * @entries: pointer to an array of MSI-X entries
 * @minvec: minimum number of MSI-X irqs requested
 * @maxvec: maximum number of MSI-X irqs requested
 *
 * Setup the MSI-X capability structure of device function with a maximum
 * possible number of interrupts in the range between @minvec and @maxvec
 * upon its software driver call to request for MSI-X mode enabled on its
 * hardware device function. It returns a negative errno if an error occurs.
 * If it succeeds, it returns the actual number of interrupts allocated and
 * indicates the successful configuration of MSI-X capability structure
 * with new allocated MSI-X interrupts.
 **/
int pci_enable_msix_range(struct pci_dev *dev, struct msix_entry *entries,
			       int minvec, int maxvec)
{
	int nvec = maxvec;
	int rc;

	if (maxvec < minvec)
		return -ERANGE;

	do {
		rc = pci_enable_msix(dev, entries, nvec);
		if (rc < 0) {
			return rc;
		} else if (rc > 0) {
			if (rc < minvec)
				return -ENOSPC;
			nvec = rc;
		}
	} while (rc);

	return nvec;
}

void __pci_write_msi_msg(struct msi_desc *entry, struct msi_msg *msg)
{
	struct pci_dev *dev = msi_desc_to_pci_dev(entry);

	if (dev->current_state != PCI_D0) {
		/* Don't touch the hardware now */
	} else if (entry->msi_attrib.is_msix) {
		void __iomem *base;
		base = entry->mask_base +
			entry->msi_attrib.entry_nr * PCI_MSIX_ENTRY_SIZE;

		writel(msg->address_lo, base + PCI_MSIX_ENTRY_LOWER_ADDR);
		writel(msg->address_hi, base + PCI_MSIX_ENTRY_UPPER_ADDR);
		writel(msg->data, base + PCI_MSIX_ENTRY_DATA);
	} else {
		int pos = dev->msi_cap;
		u16 msgctl;

		pci_read_config_word(dev, pos + PCI_MSI_FLAGS, &msgctl);
		msgctl &= ~PCI_MSI_FLAGS_QSIZE;
		msgctl |= entry->msi_attrib.multiple << 4;
		pci_write_config_word(dev, pos + PCI_MSI_FLAGS, msgctl);

		pci_write_config_dword(dev, pos + PCI_MSI_ADDRESS_LO,
				       msg->address_lo);
		if (entry->msi_attrib.is_64) {
			pci_write_config_dword(dev, pos + PCI_MSI_ADDRESS_HI,
					       msg->address_hi);
			pci_write_config_word(dev, pos + PCI_MSI_DATA_64,
					      msg->data);
		} else {
			pci_write_config_word(dev, pos + PCI_MSI_DATA_32,
					      msg->data);
		}
	}
	entry->msg = *msg;
}

void pci_write_msi_msg(unsigned int irq, struct msi_msg *msg)
{
	struct msi_desc *entry = irq_get_msi_desc(irq);

	__pci_write_msi_msg(entry, msg);
}

/**
 * pci_msi_domain_write_msg - Helper to write MSI message to PCI config space
 * @irq_data:	Pointer to interrupt data of the MSI interrupt
 * @msg:	Pointer to the message
 */
void pci_msi_domain_write_msg(struct irq_data *irq_data, struct msi_msg *msg)
{
	struct msi_desc *desc = irq_data_get_msi_desc(irq_data);

	/*
	 * For MSI-X desc->irq is always equal to irq_data->irq. For
	 * MSI only the first interrupt of MULTI MSI passes the test.
	 */
	if (desc->irq == irq_data->irq)
		__pci_write_msi_msg(desc, msg);
}

static void msi_set_mask_bit(struct irq_data *data, u32 flag)
{
	struct msi_desc *desc = irq_data_get_msi_desc(data);

	if (desc->msi_attrib.is_msix) {
		msix_mask_irq(desc, flag);
		readl(desc->mask_base);		/* Flush write to device */
	} else {
		unsigned offset = data->irq - desc->irq;
		msi_mask_irq(desc, 1 << offset, flag << offset);
	}
}

/**
 * pci_msi_mask_irq - Generic irq chip callback to mask PCI/MSI interrupts
 * @data:	pointer to irqdata associated to that interrupt
 */
void pci_msi_mask_irq(struct irq_data *data)
{
	msi_set_mask_bit(data, 1);
}

/**
 * pci_msi_unmask_irq - Generic irq chip callback to unmask PCI/MSI interrupts
 * @data:	pointer to irqdata associated to that interrupt
 */
void pci_msi_unmask_irq(struct irq_data *data)
{
	msi_set_mask_bit(data, 0);
}

static void pci_msi_domain_update_chip_ops(struct msi_domain_info *info)
{
	struct irq_chip *chip = info->chip;

	BUG_ON(!chip);
	if (!chip->irq_write_msi_msg)
		chip->irq_write_msi_msg = pci_msi_domain_write_msg;
	if (!chip->irq_mask)
		chip->irq_mask = pci_msi_mask_irq;
	if (!chip->irq_unmask)
		chip->irq_unmask = pci_msi_unmask_irq;
}

static inline bool pci_msi_desc_is_multi_msi(struct msi_desc *desc)
{
	return !desc->msi_attrib.is_msix && desc->nvec_used > 1;
}

static int pci_msi_domain_handle_error(struct irq_domain *domain,
				       struct msi_desc *desc, int error)
{
	/* Special handling to support pci_enable_msi_range() */
	if (pci_msi_desc_is_multi_msi(desc) && error == -ENOSPC)
		return 1;

	return error;
}

/**
 * pci_msi_domain_check_cap - Verify that @domain supports the capabilities for @dev
 * @domain:	The interrupt domain to check
 * @info:	The domain info for verification
 * @dev:	The device to check
 *
 * Returns:
 *  0 if the functionality is supported
 *  1 if Multi MSI is requested, but the domain does not support it
 *  -ENOTSUPP otherwise
 */
int pci_msi_domain_check_cap(struct irq_domain *domain,
			     struct msi_domain_info *info, struct device *dev)
{
	struct msi_desc *desc = first_pci_msi_entry(to_pci_dev(dev));

	/* Special handling to support pci_enable_msi_range() */
	if (pci_msi_desc_is_multi_msi(desc) &&
	    !(info->flags & MSI_FLAG_MULTI_PCI_MSI))
		return 1;
	else if (desc->msi_attrib.is_msix && !(info->flags & MSI_FLAG_PCI_MSIX))
		return -ENOTSUPP;

	return 0;
}

#define pci_msi_domain_set_desc		NULL

static struct msi_domain_ops pci_msi_domain_ops_default = {
	.set_desc	= pci_msi_domain_set_desc,
	.msi_check	= pci_msi_domain_check_cap,
	.handle_error	= pci_msi_domain_handle_error,
};

static void pci_msi_domain_update_dom_ops(struct msi_domain_info *info)
{
	struct msi_domain_ops *ops = info->ops;

	if (ops == NULL) {
		info->ops = &pci_msi_domain_ops_default;
	} else {
		if (ops->set_desc == NULL)
			ops->set_desc = pci_msi_domain_set_desc;
		if (ops->msi_check == NULL)
			ops->msi_check = pci_msi_domain_check_cap;
		if (ops->handle_error == NULL)
			ops->handle_error = pci_msi_domain_handle_error;
	}
}

/**
 * pci_msi_create_irq_domain - Create a MSI interrupt domain
 * @fwnode:	Optional fwnode of the interrupt controller
 * @info:	MSI domain info
 * @parent:	Parent irq domain
 *
 * Updates the domain and chip ops and creates a MSI interrupt domain.
 *
 * Returns:
 * A domain pointer or NULL in case of failure.
 */
struct irq_domain *pci_msi_create_irq_domain(void *fwnode,
					     struct msi_domain_info *info,
					     struct irq_domain *parent)
{
	struct irq_domain *domain;

	if (info->flags & MSI_FLAG_USE_DEF_DOM_OPS)
		pci_msi_domain_update_dom_ops(info);
	if (info->flags & MSI_FLAG_USE_DEF_CHIP_OPS)
		pci_msi_domain_update_chip_ops(info);

	info->flags |= MSI_FLAG_ACTIVATE_EARLY;

	domain = msi_create_irq_domain(fwnode, info, parent);
	if (!domain)
		return NULL;
	return domain;
}

/**
 * pci_msi_domain_calc_hwirq - Generate a unique ID for an MSI source
 * @dev:	Pointer to the PCI device
 * @desc:	Pointer to the msi descriptor
 *
 * The ID number is only used within the irqdomain.
 */
irq_hw_number_t pci_msi_domain_calc_hwirq(struct pci_dev *dev,
					  struct msi_desc *desc)
{
	return (irq_hw_number_t)desc->msi_attrib.entry_nr |
		PCI_DEVID(dev->bus->number, dev->devfn) << 11 |
		(0 & 0xFFFFFFFF) << 27;
}

/**
 * pci_msi_domain_alloc_irqs - Allocate interrupts for @dev in @domain
 * @domain:	The interrupt domain to allocate from
 * @dev:	The device for which to allocate
 * @nvec:	The number of interrupts to allocate
 * @type:	Unused to allow simpler migration from the arch_XXX interfaces
 *
 * Returns:
 * A virtual interrupt number or an error code in case of failure
 */
int pci_msi_domain_alloc_irqs(struct irq_domain *domain, struct pci_dev *dev,
			      int nvec, int type)
{
	return msi_domain_alloc_irqs(domain, &dev->dev, nvec);
}
