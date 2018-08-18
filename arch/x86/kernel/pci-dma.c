/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/dma-mapping.h>
#include <lego/types.h>
#include <lego/gfp.h>
#include <lego/pci.h>
#include <lego/mm.h>

#include <asm/dma.h>
#include <asm/page_types.h>

/* Dummy device used for NULL arguments (normally ISA). */
struct device x86_dma_fallback_dev = {
	.coherent_dma_mask = ISA_DMA_BIT_MASK,
	.dma_mask = &x86_dma_fallback_dev.coherent_dma_mask,
};

/*
 * HACK!!!
 *
 * This dma_ops is used everywhere in Lego. And this is the only
 * dma_ops in Lego as well. We don't have IOMMU support now.
 */
struct dma_map_ops *dma_ops = &nommu_dma_ops;

void *dma_generic_alloc_coherent(struct device *dev, size_t size,
				 dma_addr_t *dma_addr, gfp_t flag,
				 struct dma_attrs *attrs)
{
	unsigned long dma_mask;
	struct page *page;
	dma_addr_t addr;

	dma_mask = dma_alloc_coherent_mask(dev, flag);

	flag |= __GFP_ZERO;
again:
	page = alloc_pages_node(dev_to_node(dev), flag, get_order(size));
	if (!page)
		return NULL;

	addr = page_to_phys(page);
	if (addr + size > dma_mask) {
		__free_pages(page, get_order(size));

		if (dma_mask < DMA_BIT_MASK(32) && !(flag & GFP_DMA)) {
			flag = (flag & ~GFP_DMA32) | GFP_DMA;
			goto again;
		}

		return NULL;
	}

	*dma_addr = addr;
	return page_address(page);
}

void dma_generic_free_coherent(struct device *dev, size_t size, void *vaddr,
			       dma_addr_t dma_addr, struct dma_attrs *attrs)
{
	free_pages((unsigned long)vaddr, get_order(size));
}

int dma_supported(struct device *dev, u64 mask)
{
	struct dma_map_ops *ops = get_dma_ops(dev);

	if (ops->dma_supported)
		return ops->dma_supported(dev, mask);

	/* Copied from i386. Doesn't make much sense, because it will
	   only work for pci_alloc_coherent.
	   The caller just has to use GFP_DMA in this case. */
	if (mask < DMA_BIT_MASK(24))
		return 0;

	return 1;
}
