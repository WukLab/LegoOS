/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_X86_DMA_MAPPING_H_
#define _ASM_X86_DMA_MAPPING_H_

/*
 * IOMMU interface. See Documentation/DMA-API-HOWTO.txt and
 * Documentation/DMA-API.txt for documentation.
 */

#include <asm/io.h>

#ifdef CONFIG_ISA
# define ISA_DMA_BIT_MASK DMA_BIT_MASK(24)
#else
# define ISA_DMA_BIT_MASK DMA_BIT_MASK(32)
#endif

#define DMA_ERROR_CODE	0

struct pci_dev;
struct device;

extern struct pci_dev x86_dma_fallback_dev;
extern int panic_on_overflow;

extern struct dma_map_ops *dma_ops;

#define get_dma_ops(_x)		(dma_ops)

bool arch_dma_alloc_attrs(struct pci_dev **dev, gfp_t *gfp);
#define arch_dma_alloc_attrs arch_dma_alloc_attrs

#define HAVE_ARCH_DMA_SUPPORTED 1
extern void *dma_generic_alloc_coherent(struct pci_dev *dev, size_t size,
					dma_addr_t *dma_addr, gfp_t flag,
					unsigned long attrs);

extern void dma_generic_free_coherent(struct pci_dev *dev, size_t size,
				      void *vaddr, dma_addr_t dma_addr,
				      unsigned long attrs);

static inline bool dma_capable(struct pci_dev *dev, dma_addr_t addr, size_t size)
{
	if (!dev->dma_mask)
		return 0;

	return addr + size - 1 <= *dev->dma_mask;
}

static inline dma_addr_t phys_to_dma(struct pci_dev *dev, phys_addr_t paddr)
{
	return paddr;
}

static inline phys_addr_t dma_to_phys(struct pci_dev *dev, dma_addr_t daddr)
{
	return daddr;
}

static inline void
dma_cache_sync(struct pci_dev *dev, void *vaddr, size_t size,
	enum dma_data_direction dir)
{
	flush_write_buffers();
}

static inline unsigned long dma_alloc_coherent_mask(struct pci_dev *dev,
						    gfp_t gfp)
{
	unsigned long dma_mask = 0;

	dma_mask = dev->coherent_dma_mask;
	if (!dma_mask)
		dma_mask = (gfp & GFP_DMA) ? DMA_BIT_MASK(24) : DMA_BIT_MASK(32);

	return dma_mask;
}

static inline gfp_t dma_alloc_coherent_gfp_flags(struct pci_dev *dev, gfp_t gfp)
{
	unsigned long dma_mask = dma_alloc_coherent_mask(dev, gfp);

	if (dma_mask <= DMA_BIT_MASK(24))
		gfp |= GFP_DMA;
	if (dma_mask <= DMA_BIT_MASK(32) && !(gfp & GFP_DMA))
		gfp |= GFP_DMA32;
       return gfp;
}

int dma_supported(struct device *dev, u64 mask);

static inline int dma_set_mask(struct device *dev, u64 mask)
{
	if (!dev->dma_mask || !dma_supported(dev, mask))
		return -EIO;

	*dev->dma_mask = mask;

	return 0;
}

static inline int dma_set_coherent_mask(struct device *dev, u64 mask)
{
	if (!dma_supported(dev, mask))
		return -EIO;
	dev->coherent_dma_mask = mask;
	return 0;
}

#endif /* _ASM_X86_DMA_MAPPING_H_ */
