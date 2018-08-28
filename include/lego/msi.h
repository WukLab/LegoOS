/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_MSI_H_
#define _LEGO_MSI_H_

#include <lego/irq.h>
#include <lego/types.h>
#include <lego/cpumask.h>
#include <asm/io_apic.h>
#include <asm/msi.h>

typedef struct irq_alloc_info msi_alloc_info_t;

struct msi_msg {
	u32	address_lo;	/* low 32 bits of msi message address */
	u32	address_hi;	/* high 32 bits of msi message address */
	u32	data;		/* 16 bits of msi message data */
};

/**
 * struct msi_desc - Descriptor structure for MSI based interrupts
 * @list:	List head for management
 * @irq:	The base interrupt number
 * @nvec_used:	The number of vectors used
 * @msg:	The last set MSI message cached for reuse
 * @affinity:	Optional pointer to a cpu affinity mask for this descriptor
 */
struct msi_desc {
	/* Shared device/bus type independent data */
	struct list_head		list;
	unsigned int			irq;
	unsigned int			nvec_used;
	struct msi_msg			msg;
	struct cpumask			*affinity;
	struct pci_dev			*dev;

	/* PCI MSI/X specific data */
	struct {
		__u8	is_msix	: 1;
		__u8	multiple: 3;	/* log2 number of messages */
		__u8	maskbit	: 1; 	/* mask-pending bit supported ?   */
		__u8	is_64	: 1;	/* Address size: 0=32bit 1=64bit  */
		__u8	pos;	 	/* Location of the msi capability */
		__u16	entry_nr;    	/* specific enabled entry 	  */
		unsigned default_irq;	/* default pre-assigned irq	  */
	} msi_attrib;
	u32			masked;                     /* mask bits */
	union {
		void __iomem	*mask_base;
		u8		mask_pos;
	};
};

/* Helpers to hide struct msi_desc implementation details */
#define first_msi_entry(pdev)		\
	list_first_entry(&(pdev)->msi_list, struct msi_desc, list)

#define first_pci_msi_entry(pdev)	first_msi_entry(pdev)

#define for_each_msi_entry(desc, pdev)	\
	list_for_each_entry((desc), (&(pdev)->msi_list), list)

/* Helper functions */
struct irq_data;
struct msi_desc;
struct irq_domain;
struct msi_domain_info;

void mask_msi_irq(struct irq_data *data);
void unmask_msi_irq(struct irq_data *data);
void __read_msi_msg(struct msi_desc *entry, struct msi_msg *msg);
void __get_cached_msi_msg(struct msi_desc *entry, struct msi_msg *msg);
void __write_msi_msg(struct msi_desc *entry, struct msi_msg *msg);
void read_msi_msg(unsigned int irq, struct msi_msg *msg);
void get_cached_msi_msg(unsigned int irq, struct msi_msg *msg);
void write_msi_msg(unsigned int irq, struct msi_msg *msg);

/* Flags for msi_domain_info */
enum {
	/*
	 * Init non implemented ops callbacks with default MSI domain
	 * callbacks.
	 */
	MSI_FLAG_USE_DEF_DOM_OPS	= (1 << 0),
	/*
	 * Init non implemented chip callbacks with default MSI chip
	 * callbacks.
	 */
	MSI_FLAG_USE_DEF_CHIP_OPS	= (1 << 1),
	/* Support multiple PCI MSI interrupts */
	MSI_FLAG_MULTI_PCI_MSI		= (1 << 2),
	/* Support PCI MSIX interrupts */
	MSI_FLAG_PCI_MSIX		= (1 << 3),
	/* Needs early activate, required for PCI */
	MSI_FLAG_ACTIVATE_EARLY		= (1 << 4),
};

/**
 * struct msi_domain_ops - MSI interrupt domain callbacks
 * @get_hwirq:		Retrieve the resulting hw irq number
 * @msi_init:		Domain specific init function for MSI interrupts
 * @msi_free:		Domain specific function to free a MSI interrupts
 * @msi_check:		Callback for verification of the domain/info/dev data
 * @msi_prepare:	Prepare the allocation of the interrupts in the domain
 * @msi_finish:		Optional callbacl to finalize the allocation
 * @set_desc:		Set the msi descriptor for an interrupt
 * @handle_error:	Optional error handler if the allocation fails
 *
 * @get_hwirq, @msi_init and @msi_free are callbacks used by
 * msi_create_irq_domain() and related interfaces
 *
 * @msi_check, @msi_prepare, @msi_finish, @set_desc and @handle_error
 * are callbacks used by msi_irq_domain_alloc_irqs() and related
 * interfaces which are based on msi_desc.
 */
struct msi_domain_ops {
	irq_hw_number_t	(*get_hwirq)(struct msi_domain_info *info,
				     msi_alloc_info_t *arg);
	int		(*msi_init)(struct irq_domain *domain,
				    struct msi_domain_info *info,
				    unsigned int virq, irq_hw_number_t hwirq,
				    msi_alloc_info_t *arg);
	void		(*msi_free)(struct irq_domain *domain,
				    struct msi_domain_info *info,
				    unsigned int virq);
	int		(*msi_check)(struct irq_domain *domain,
				     struct msi_domain_info *info,
				     struct device *dev);
	int		(*msi_prepare)(struct irq_domain *domain,
				       struct device *dev, int nvec,
				       msi_alloc_info_t *arg);
	void		(*msi_finish)(msi_alloc_info_t *arg, int retval);
	void		(*set_desc)(msi_alloc_info_t *arg,
				    struct msi_desc *desc);
	int		(*handle_error)(struct irq_domain *domain,
					struct msi_desc *desc, int error);
};

/**
 * struct msi_domain_info - MSI interrupt domain data
 * @flags:		Flags to decribe features and capabilities
 * @ops:		The callback data structure
 * @chip:		Optional: associated interrupt chip
 * @chip_data:		Optional: associated interrupt chip data
 * @handler:		Optional: associated interrupt flow handler
 * @handler_data:	Optional: associated interrupt flow handler data
 * @handler_name:	Optional: associated interrupt flow handler name
 * @data:		Optional: domain specific data
 */
struct msi_domain_info {
	u32			flags;
	struct msi_domain_ops	*ops;
	struct irq_chip		*chip;
	void			*chip_data;
	irq_flow_handler_t	handler;
	void			*handler_data;
	const char		*handler_name;
	void			*data;
};

struct irq_domain *msi_create_irq_domain(void *fwnode,
					 struct msi_domain_info *info,
					 struct irq_domain *parent);
struct irq_domain *pci_msi_create_irq_domain(void *fwnode,
					     struct msi_domain_info *info,
					     struct irq_domain *parent);

irq_hw_number_t pci_msi_domain_calc_hwirq(struct pci_dev *dev,
					  struct msi_desc *desc);

u32 __pci_msix_desc_mask_irq(struct msi_desc *desc, u32 flag);
u32 __pci_msi_desc_mask_irq(struct msi_desc *desc, u32 mask, u32 flag);
void pci_msi_mask_irq(struct irq_data *data);
void pci_msi_unmask_irq(struct irq_data *data);

int pci_msi_domain_alloc_irqs(struct irq_domain *domain, struct pci_dev *dev,
			      int nvec, int type);

int msi_domain_alloc_irqs(struct irq_domain *domain, struct device *dev,
			  int nvec);

#endif /* _LEGO_MSI_H_ */
