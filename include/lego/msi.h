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

#include <lego/types.h>
#include <lego/cpumask.h>

#include <asm/msi.h>

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

/* Helper functions */
struct irq_data;
struct msi_desc;
void mask_msi_irq(struct irq_data *data);
void unmask_msi_irq(struct irq_data *data);
void __read_msi_msg(struct msi_desc *entry, struct msi_msg *msg);
void __get_cached_msi_msg(struct msi_desc *entry, struct msi_msg *msg);
void __write_msi_msg(struct msi_desc *entry, struct msi_msg *msg);
void read_msi_msg(unsigned int irq, struct msi_msg *msg);
void get_cached_msi_msg(unsigned int irq, struct msi_msg *msg);
void write_msi_msg(unsigned int irq, struct msi_msg *msg);

#endif /* _LEGO_MSI_H_ */
