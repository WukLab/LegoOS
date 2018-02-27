/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_EARLY_IOREMAP_H_
#define _LEGO_EARLY_IOREMAP_H_

#include <lego/types.h>

/*
 * early_ioremap() and early_iounmap() are for temporary early boot-time
 * mappings, before the real ioremap() is functional.
 */
void *early_ioremap(resource_size_t phys_addr, unsigned long size);
void *early_memremap(resource_size_t phys_addr, unsigned long size);
void early_iounmap(void *addr, unsigned long size);
void early_memunmap(void *addr, unsigned long size);

/* Arch-specific initialization */
void early_ioremap_init(void);

/* Generic initialization called by architecture code */
void early_ioremap_setup(void);

/* Early copy from unmapped memory to kernel mapped memory */
void copy_from_early_mem(void *dest, phys_addr_t src, unsigned long size);

extern int early_ioremap_debug;

#endif /* _LEGO_EARLY_IOREMAP_H_ */
