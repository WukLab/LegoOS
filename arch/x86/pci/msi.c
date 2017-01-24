/*
 * File:	msi.c
 * Purpose:	PCI Message Signaled Interrupt (MSI)
 *
 * Copyright (C) 2003-2004 Intel
 * Copyright (C) Tom Long Nguyen (tom.l.nguyen@intel.com)
 */

#include <lego/err.h>
#include <lego/mm.h>
#include <lego/irqdesc.h>
//#include <lego/interrupt.h>
#include <lego/init.h>
//#include <lego/ioport.h>
#include <lego/pci.h>
#include <asm/pci.h>
//#include <lego/msi.h>
#include <lego/smp.h>
#include <lego/errno.h>
#include <asm/io.h>
#include <lego/slab.h>

static int pci_msi_enable = 1;

#define msix_table_size(flags)	((flags & PCI_MSIX_FLAGS_QSIZE) + 1)

static void msi_set_enable(struct pci_dev *dev, int enable)
{
	u16 control;

	control = pci_conf_read(dev, dev->msi_cap + PCI_MSI_FLAGS, 2);
	control &= ~PCI_MSI_FLAGS_ENABLE;
	if (enable)
		control |= PCI_MSI_FLAGS_ENABLE;
	pci_conf_write(dev, dev->msi_cap + PCI_MSI_FLAGS, control, 2);
}

static void msix_set_enable(struct pci_dev *dev, int enable)
{
	u16 control;

	control = pci_conf_read(dev, dev->msix_cap + PCI_MSIX_FLAGS, 2);
	control &= ~PCI_MSIX_FLAGS_ENABLE;
	if (enable)
		control |= PCI_MSIX_FLAGS_ENABLE;
	pci_conf_write(dev, dev->msix_cap + PCI_MSIX_FLAGS, control, 2);
}

static inline __attribute_const__ u32 msi_mask(unsigned x)
{
	/* Don't shift by >= width of type */
	if (x >= 5)
		return 0xffffffff;
	return (1 << (1 << x)) - 1;
}

static inline __attribute_const__ u32 msi_capable_mask(u16 control)
{
	return msi_mask((control >> 1) & 7);
}

static inline __attribute_const__ u32 msi_enabled_mask(u16 control)
{
	return msi_mask((control >> 4) & 7);
}

/*
 * PCI 2.3 does not specify mask bits for each MSI interrupt.  Attempting to
 * mask all MSI interrupts by clearing the MSI enable bit does not work
 * reliably as devices without an INTx disable bit will then generate a
 * level IRQ which will never be cleared.
 */
static u32 __msi_mask_irq(struct msi_desc *desc, u32 mask, u32 flag)
{
	u32 mask_bits = desc->masked;

	if (!desc->msi_attrib.maskbit)
		return 0;

	mask_bits &= ~mask;
	mask_bits |= flag;
	pci_conf_write(desc->dev, desc->mask_pos, mask_bits, 3);

	return mask_bits;
}

static void msi_mask_irq(struct msi_desc *desc, u32 mask, u32 flag)
{
	desc->masked = __msi_mask_irq(desc, mask, flag);
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

#ifdef CONFIG_GENERIC_HARDIRQS

static void msi_set_mask_bit(struct irq_data *data, u32 flag)
{
	struct msi_desc *desc = irq_data_get_msi(data);

	if (desc->msi_attrib.is_msix) {
		msix_mask_irq(desc, flag);
		readl(desc->mask_base);		/* Flush write to device */
	} else {
		unsigned offset = data->irq - desc->dev->irq;
		msi_mask_irq(desc, 1 << offset, flag << offset);
	}
}

void mask_msi_irq(struct irq_data *data)
{
	msi_set_mask_bit(data, 1);
}

void unmask_msi_irq(struct irq_data *data)
{
	msi_set_mask_bit(data, 0);
}

#endif /* CONFIG_GENERIC_HARDIRQS */

void __read_msi_msg(struct msi_desc *entry, struct msi_msg *msg)
{
//	BUG_ON(entry->dev->current_state != PCI_D0);

	if (entry->msi_attrib.is_msix) {
		void __iomem *base = entry->mask_base +
			entry->msi_attrib.entry_nr * PCI_MSIX_ENTRY_SIZE;

		msg->address_lo = readl(base + PCI_MSIX_ENTRY_LOWER_ADDR);
		msg->address_hi = readl(base + PCI_MSIX_ENTRY_UPPER_ADDR);
		msg->data = readl(base + PCI_MSIX_ENTRY_DATA);
	} else {
		struct pci_dev *dev = entry->dev;
		int pos = dev->msi_cap;
		u16 data;

		msg->address_lo = pci_conf_read(dev, pos + PCI_MSI_ADDRESS_LO, 3);
		if (entry->msi_attrib.is_64) {
			msg->address_hi = pci_conf_read(dev, pos + PCI_MSI_ADDRESS_HI, 3);
			data = pci_conf_read(dev, pos + PCI_MSI_DATA_64, 2);
		} else {
			msg->address_hi = 0;
			data = pci_conf_read(dev, pos + PCI_MSI_DATA_32, 2);
		}
		msg->data = data;
	}
}

void read_msi_msg(unsigned int irq, struct msi_msg *msg)
{
	struct msi_desc *entry = irq_get_msi_desc(irq);

	__read_msi_msg(entry, msg);
}

void __get_cached_msi_msg(struct msi_desc *entry, struct msi_msg *msg)
{
	/* Assert that the cache is valid, assuming that
	 * valid messages are not all-zeroes. */
	BUG_ON(!(entry->msg.address_hi | entry->msg.address_lo |
		 entry->msg.data));

	*msg = entry->msg;
}

void get_cached_msi_msg(unsigned int irq, struct msi_msg *msg)
{
	struct msi_desc *entry = irq_get_msi_desc(irq);

	__get_cached_msi_msg(entry, msg);
}

void __write_msi_msg(struct msi_desc *entry, struct msi_msg *msg)
{
//	if (entry->dev->current_state != PCI_D0) {
		/* Don't touch the hardware now */
//	} else if (entry->msi_attrib.is_msix) {
	if (entry->msi_attrib.is_msix) {
		void __iomem *base;
		base = entry->mask_base +
			entry->msi_attrib.entry_nr * PCI_MSIX_ENTRY_SIZE;

		writel(msg->address_lo, base + PCI_MSIX_ENTRY_LOWER_ADDR);
		writel(msg->address_hi, base + PCI_MSIX_ENTRY_UPPER_ADDR);
		writel(msg->data, base + PCI_MSIX_ENTRY_DATA);
	} else {
		struct pci_dev *dev = entry->dev;
		int pos = dev->msi_cap;
		u16 msgctl;

		msgctl = pci_conf_read(dev, pos + PCI_MSI_FLAGS, 2);
		msgctl &= ~PCI_MSI_FLAGS_QSIZE;
		msgctl |= entry->msi_attrib.multiple << 4;
		pci_conf_write(dev, pos + PCI_MSI_FLAGS, msgctl, 2);

		pci_conf_write(dev, pos + PCI_MSI_ADDRESS_LO,
				       msg->address_lo, 3);
		if (entry->msi_attrib.is_64) {
			pci_conf_write(dev, pos + PCI_MSI_ADDRESS_HI,
					       msg->address_hi, 3);
			pci_conf_write(dev, pos + PCI_MSI_DATA_64, msg->data, 2);
		} else {
			pci_conf_write(dev, pos + PCI_MSI_DATA_32, msg->data, 2);
		}
	}
	entry->msg = *msg;
}

void write_msi_msg(unsigned int irq, struct msi_msg *msg)
{
	struct msi_desc *entry = irq_get_msi_desc(irq);

	__write_msi_msg(entry, msg);
}

static void free_msi_irqs(struct pci_dev *dev)
{
	struct msi_desc *entry, *tmp;
	int nvec;

	list_for_each_entry(entry, &dev->msi_list, list) {
		if (!entry->irq)
			continue;
		if (entry->nvec_used)
			nvec = entry->nvec_used;
		else
			nvec = 1 << entry->msi_attrib.multiple;
#ifdef CONFIG_GENERIC_HARDIRQS
		for (i = 0; i < nvec; i++)
			BUG_ON(irq_has_action(entry->irq + i));
#endif
	}

// XXX	arch_teardown_msi_irqs(dev);

	list_for_each_entry_safe(entry, tmp, &dev->msi_list, list) {
		if (entry->msi_attrib.is_msix) {
			if (list_is_last(&entry->list, &dev->msi_list))
				iounmap(entry->mask_base);
		}

		list_del(&entry->list);
		kfree(entry);
	}
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

/**
 * pci_intx - enables/disables PCI INTx for device dev
 * @pdev: the PCI device to operate on
 * @enable: boolean: whether to enable or disable PCI INTx
 *
 * Enables/disables PCI INTx for device dev
 */
void
pci_intx(struct pci_dev *pdev, int enable)
{
        u16 pci_command, new;

        pci_command = pci_conf_read(pdev, PCI_COMMAND, 2);
 
        if (enable) {
                new = pci_command & ~PCI_COMMAND_INTX_DISABLE;
        } else {
                new = pci_command | PCI_COMMAND_INTX_DISABLE;
        }

        if (new != pci_command) {
                 pci_conf_write(pdev, PCI_COMMAND, new, 2);
        }
}

static void pci_intx_for_msi(struct pci_dev *dev, int enable)
{
//	if (!(dev->dev_flags & PCI_DEV_FLAGS_MSI_INTX_DISABLE_BUG))
		pci_intx(dev, enable);
}

static void __pci_restore_msi_state(struct pci_dev *dev)
{
	u16 control;
	struct msi_desc *entry;

	if (!dev->msi_enabled)
		return;

	entry = irq_get_msi_desc(dev->irq);

	pci_intx_for_msi(dev, 0);
	msi_set_enable(dev, 0);
//XXX	arch_restore_msi_irqs(dev, dev->irq);

	control = pci_conf_read(dev, dev->msi_cap + PCI_MSI_FLAGS, 2);
	msi_mask_irq(entry, msi_capable_mask(control), entry->masked);
	control &= ~PCI_MSI_FLAGS_QSIZE;
	control |= (entry->msi_attrib.multiple << 4) | PCI_MSI_FLAGS_ENABLE;
	pci_conf_write(dev, dev->msi_cap + PCI_MSI_FLAGS, control, 2);
}

static void __pci_restore_msix_state(struct pci_dev *dev)
{
	struct msi_desc *entry;
	u16 control;

	if (!dev->msix_enabled)
		return;
	BUG_ON(list_empty(&dev->msi_list));
	entry = list_first_entry(&dev->msi_list, struct msi_desc, list);
	control = pci_conf_read(dev, dev->msix_cap + PCI_MSIX_FLAGS, 2);

	/* route the table */
	pci_intx_for_msi(dev, 0);
	control |= PCI_MSIX_FLAGS_ENABLE | PCI_MSIX_FLAGS_MASKALL;
	pci_conf_write(dev, dev->msix_cap + PCI_MSIX_FLAGS, control, 2);

	list_for_each_entry(entry, &dev->msi_list, list) {
//XXX		arch_restore_msi_irqs(dev, entry->irq);
		msix_mask_irq(entry, entry->masked);
	}

	control &= ~PCI_MSIX_FLAGS_MASKALL;
	pci_conf_write(dev, dev->msix_cap + PCI_MSIX_FLAGS, control, 2);
}

void pci_restore_msi_state(struct pci_dev *dev)
{
	__pci_restore_msi_state(dev);
	__pci_restore_msix_state(dev);
}


/**
 * msi_capability_init - configure device's MSI capability structure
 * @dev: pointer to the pci_dev data structure of MSI device function
 * @nvec: number of interrupts to allocate
 *
 * Setup the MSI capability structure of the device with the requested
 * number of interrupts.  A return value of zero indicates the successful
 * setup of an entry with the new MSI irq.  A negative return value indicates
 * an error, and a positive return value indicates the number of interrupts
 * which could have been allocated.
 */
static int msi_capability_init(struct pci_dev *dev, int nvec)
{
	struct msi_desc *entry;
	u16 control;
	unsigned mask;

	msi_set_enable(dev, 0);	/* Disable MSI during set up */

	control = pci_conf_read(dev, dev->msi_cap + PCI_MSI_FLAGS, 2);
	/* MSI Entry Initialization */
	entry = alloc_msi_entry(dev);
	if (!entry)
		return -ENOMEM;

	entry->msi_attrib.is_msix	= 0;
	entry->msi_attrib.is_64		= !!(control & PCI_MSI_FLAGS_64BIT);
	entry->msi_attrib.entry_nr	= 0;
	entry->msi_attrib.maskbit	= !!(control & PCI_MSI_FLAGS_MASKBIT);
	entry->msi_attrib.default_irq	= dev->irq;	/* Save IOAPIC IRQ */
	entry->msi_attrib.pos		= dev->msi_cap;

	if (control & PCI_MSI_FLAGS_64BIT)
		entry->mask_pos = dev->msi_cap + PCI_MSI_MASK_64;
	else
		entry->mask_pos = dev->msi_cap + PCI_MSI_MASK_32;
	/* All MSIs are unmasked by default, Mask them all */
	if (entry->msi_attrib.maskbit)
		pci_conf_read(dev, entry->mask_pos, (entry->masked));
	mask = msi_capable_mask(control);
	msi_mask_irq(entry, mask, mask);

	list_add_tail(&entry->list, &dev->msi_list);

	/* Configure MSI capability structure */
//XXX	ret = arch_setup_msi_irqs(dev, nvec, PCI_CAP_MSI);
//	if (ret) {
//		msi_mask_irq(entry, mask, ~mask);
//		free_msi_irqs(dev);
//		return ret;
//	}

	/* Set MSI enabled bits	 */
	pci_intx_for_msi(dev, 0);
	msi_set_enable(dev, 1);
	dev->msi_enabled = 1;

	dev->irq = entry->irq;
	return 0;
}

static void __iomem *msix_map_region(struct pci_dev *dev, unsigned nr_entries)
{
	resource_size_t phys_addr;
	u32 table_offset;
	u8 bir;

	table_offset = pci_conf_read(dev, dev->msix_cap + PCI_MSIX_TABLE, 3);
	bir = (u8)(table_offset & PCI_MSIX_TABLE_BIR);
	table_offset &= PCI_MSIX_TABLE_OFFSET;
	phys_addr = pci_resource_start(dev, bir) + table_offset;

	return ioremap_nocache(phys_addr, nr_entries * PCI_MSIX_ENTRY_SIZE);
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
// XXX		irq_set_msi_desc(entry->irq, entry);
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

	control = pci_conf_read(dev, dev->msix_cap + PCI_MSIX_FLAGS, 2);

	/* Ensure MSI-X is disabled while it is set up */
	control &= ~PCI_MSIX_FLAGS_ENABLE;
	pci_conf_write(dev, dev->msix_cap + PCI_MSIX_FLAGS, control, 2);

	/* Request & Map MSI-X table region */
	base = msix_map_region(dev, msix_table_size(control));
	if (!base)
		return -ENOMEM;

	ret = msix_setup_entries(dev, base, entries, nvec);
	if (ret)
		return ret;

// XXX	ret = arch_setup_msi_irqs(dev, nvec, PCI_CAP_MSIX);
//	if (ret)
//		goto error;

	/*
	 * Some devices require MSI-X to be enabled before we can touch the
	 * MSI-X registers.  We need to mask all the vectors to prevent
	 * interrupts coming in before they're fully set up.
	 */
	control |= PCI_MSIX_FLAGS_MASKALL | PCI_MSIX_FLAGS_ENABLE;
	pci_conf_write(dev, dev->msix_cap + PCI_MSIX_FLAGS, control, 2);

	msix_program_entries(dev, entries);

	/* Set MSI-X enabled bits and unmask the function */
	pci_intx_for_msi(dev, 0);
	dev->msix_enabled = 1;

	control &= ~PCI_MSIX_FLAGS_MASKALL;
	pci_conf_write(dev, dev->msix_cap + PCI_MSIX_FLAGS, control, 2);

	return 0;

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
 * pci_enable_msi_block - configure device's MSI capability structure
 * @dev: device to configure
 * @nvec: number of interrupts to configure
 *
 * Allocate IRQs for a device with the MSI capability.
 * This function returns a negative errno if an error occurs.  If it
 * is unable to allocate the number of interrupts requested, it returns
 * the number of interrupts it might be able to allocate.  If it successfully
 * allocates at least the number of interrupts requested, it returns 0 and
 * updates the @dev's irq member to the lowest new interrupt number; the
 * other interrupt numbers allocated to this device are consecutive.
 */
int pci_enable_msi_block(struct pci_dev *dev, unsigned int nvec)
{
	int status, maxvec;
	u16 msgctl;

	if (!dev->msi_cap)
		return -EINVAL;

	msgctl = pci_conf_read(dev, dev->msi_cap + PCI_MSI_FLAGS, 2);
	maxvec = 1 << ((msgctl & PCI_MSI_FLAGS_QMASK) >> 1);
	if (nvec > maxvec)
		return maxvec;

	WARN_ON(!!dev->msi_enabled);

	/* Check whether driver already requested MSI-X irqs */
	if (dev->msix_enabled) {
		pr_info("can't enable MSI "
			 "(MSI-X already enabled)\n");
		return -EINVAL;
	}

	status = msi_capability_init(dev, nvec);
	return status;
}

int pci_enable_msi_block_auto(struct pci_dev *dev, unsigned int *maxvec)
{
	int ret, nvec;
	u16 msgctl;

	if (!dev->msi_cap)
		return -EINVAL;

	msgctl = pci_conf_read(dev, dev->msi_cap + PCI_MSI_FLAGS, 2);
	ret = 1 << ((msgctl & PCI_MSI_FLAGS_QMASK) >> 1);

	if (maxvec)
		*maxvec = ret;

	do {
		nvec = ret;
		ret = pci_enable_msi_block(dev, nvec);
	} while (ret > 0);

	if (ret < 0)
		return ret;
	return nvec;
}

void pci_msi_shutdown(struct pci_dev *dev)
{
	struct msi_desc *desc;
	u32 mask;
	u16 ctrl;

	if (!pci_msi_enable || !dev || !dev->msi_enabled)
		return;

	BUG_ON(list_empty(&dev->msi_list));
	desc = list_first_entry(&dev->msi_list, struct msi_desc, list);

	msi_set_enable(dev, 0);
	pci_intx_for_msi(dev, 1);
	dev->msi_enabled = 0;

	/* Return the device with MSI unmasked as initial states */
	ctrl = pci_conf_read(dev, dev->msi_cap + PCI_MSI_FLAGS, 2);
	mask = msi_capable_mask(ctrl);
	/* Keep cached state to be restored */
	__msi_mask_irq(desc, mask, ~mask);

	/* Restore dev->irq to its default pin-assertion irq */
	dev->irq = desc->msi_attrib.default_irq;
}

void pci_disable_msi(struct pci_dev *dev)
{
	if (!pci_msi_enable || !dev || !dev->msi_enabled)
		return;

	pci_msi_shutdown(dev);
	free_msi_irqs(dev);
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

	control = pci_conf_read(dev, dev->msix_cap + PCI_MSIX_FLAGS, 2);
	return msix_table_size(control);
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
		pr_info("can't enable MSI-X "
		       "(MSI IRQ already assigned)\n");
		return -EINVAL;
	}
	status = msix_capability_init(dev, entries, nvec);
	return status;
}

void pci_msix_shutdown(struct pci_dev *dev)
{
	struct msi_desc *entry;

	if (!pci_msi_enable || !dev || !dev->msix_enabled)
		return;

	/* Return the device with MSI-X masked as initial states */
	list_for_each_entry(entry, &dev->msi_list, list) {
		/* Keep cached states to be restored */
		__msix_mask_irq(entry, 1);
	}

	msix_set_enable(dev, 0);
	pci_intx_for_msi(dev, 1);
	dev->msix_enabled = 0;
}

void pci_disable_msix(struct pci_dev *dev)
{
	if (!pci_msi_enable || !dev || !dev->msix_enabled)
		return;

	pci_msix_shutdown(dev);
	free_msi_irqs(dev);
}

/**
 * msi_remove_pci_irq_vectors - reclaim MSI(X) irqs to unused state
 * @dev: pointer to the pci_dev data structure of MSI(X) device function
 *
 * Being called during hotplug remove, from which the device function
 * is hot-removed. All previous assigned MSI/MSI-X irqs, if
 * allocated for this device function, are reclaimed to unused state,
 * which may be used later on.
 **/
void msi_remove_pci_irq_vectors(struct pci_dev *dev)
{
	if (!pci_msi_enable || !dev)
		return;

	if (dev->msi_enabled || dev->msix_enabled)
		free_msi_irqs(dev);
}

void pci_no_msi(void)
{
	pci_msi_enable = 0;
}

/**
 * pci_msi_enabled - is MSI enabled?
 *
 * Returns true if MSI has not been disabled by the command-line option
 * pci=nomsi.
 **/
int pci_msi_enabled(void)
{
	return pci_msi_enable;
}

void pci_msi_init_pci_dev(struct pci_dev *dev)
{
	INIT_LIST_HEAD(&dev->msi_list);

	/* Disable the msi hardware to avoid screaming interrupts
	 * during boot.  This is the power on reset default so
	 * usually this should be a noop.
	 */
//	dev->msi_cap = pci_find_capability(dev, PCI_CAP_MSI);
//	if (dev->msi_cap)
//		msi_set_enable(dev, 0);

//	dev->msix_cap = pci_find_capability(dev, PCI_CAP_MSIX);
//	if (dev->msix_cap)
		msix_set_enable(dev, 0);
}
