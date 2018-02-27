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

struct dma_map_ops *dma_ops = &nommu_dma_ops;

void *dma_generic_alloc_coherent(struct pci_dev *pcid, size_t size,
				 dma_addr_t *dma_addr, gfp_t flag,
				 unsigned long attrs)
{
	unsigned long dma_mask;
	struct page *page;
	dma_addr_t addr;

	//pr_debug("%s\n", __func__);
	dma_mask = dma_alloc_coherent_mask(pcid, flag);

	flag &= ~__GFP_ZERO;

	page = alloc_pages(flag, get_order(size));
	if (!page)
		return NULL;
/*
	pr_debug("%s mask %lx size %d got page %p\n", 
			__func__, dma_mask, size, page);
*/
	addr = page_to_phys(page);
	if (addr + size > dma_mask) {
/*
		pr_debug("addr %lx + size %lx bigger than dma_mask %lx\n",
				addr, addr+size, dma_mask);
*/
	//	__free_pages(page, get_order(size));

	//	if (dma_mask < DMA_BIT_MASK(32) && !(flag & GFP_DMA)) {
	//		flag = (flag & ~GFP_DMA32) | GFP_DMA;
	//		goto again;
	//	}

	//	return NULL;
	}
	memset(page_address(page), 0, size);
	*dma_addr = addr;
	return page_address(page);
}

void dma_generic_free_coherent(struct pci_dev *pcid, size_t size, void *vaddr,
			       dma_addr_t dma_addr, unsigned long attrs)
{
	free_pages((unsigned long)vaddr, get_order(size));
}

bool arch_dma_alloc_attrs(struct pci_dev **pcid, gfp_t *gfp)
{
	BUG_ON(!*pcid);

	*gfp &= ~(__GFP_DMA | __GFP_HIGHMEM | __GFP_DMA32);
	*gfp = dma_alloc_coherent_gfp_flags(*pcid, *gfp);

	//pr_debug("%s\n", __func__);
//	if (!is_device_dma_capable(*pcid))
//		return false;
	return true;

}
