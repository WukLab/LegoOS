/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
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
};

#endif /* _LEGO_MSI_H_ */
