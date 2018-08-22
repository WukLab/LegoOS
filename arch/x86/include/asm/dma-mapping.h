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

struct device;

extern struct device x86_dma_fallback_dev;
extern int panic_on_overflow;

extern struct dma_map_ops *dma_ops;

/*
 * HACK!!!
 *
 * We are not supporting IOMMU, nor do we support weird x86 platforms.
 * We can simply use the direct dma ops.
 */
#define get_dma_ops(_x)		(dma_ops)

bool arch_dma_alloc_attrs(struct device **dev, gfp_t *gfp);
#define arch_dma_alloc_attrs arch_dma_alloc_attrs

#define HAVE_ARCH_DMA_SUPPORTED 1

static inline bool dma_capable(struct device *dev, dma_addr_t addr, size_t size)
{
	if (!dev->dma_mask)
		return 0;

	return addr + size - 1 <= *dev->dma_mask;
}

/*
 * In x86, without IOMMU, life is simple.
 * There is a one-to-one mapping between physical and DMA address.
 */
static inline dma_addr_t phys_to_dma(struct device *dev, phys_addr_t paddr)
{
	return paddr;
}

static inline phys_addr_t dma_to_phys(struct device *dev, dma_addr_t daddr)
{
	return daddr;
}

static inline void
dma_cache_sync(struct device *dev, void *vaddr, size_t size,
	enum dma_data_direction dir)
{
	flush_write_buffers();
}

static inline unsigned long dma_alloc_coherent_mask(struct device *dev,
						    gfp_t gfp)
{
	unsigned long dma_mask = 0;

	dma_mask = dev->coherent_dma_mask;
	if (!dma_mask)
		dma_mask = (gfp & GFP_DMA) ? DMA_BIT_MASK(24) : DMA_BIT_MASK(32);

	return dma_mask;
}

static inline gfp_t dma_alloc_coherent_gfp_flags(struct device *dev, gfp_t gfp)
{
	unsigned long dma_mask = dma_alloc_coherent_mask(dev, gfp);

	if (dma_mask <= DMA_BIT_MASK(24))
		gfp |= GFP_DMA;
#ifdef CONFIG_X86_64
	if (dma_mask <= DMA_BIT_MASK(32) && !(gfp & GFP_DMA))
		gfp |= GFP_DMA32;
#endif
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

void *dma_generic_alloc_coherent(struct device *dev, size_t size,
				 dma_addr_t *dma_addr, gfp_t flag,
				 struct dma_attrs *attrs);
void dma_generic_free_coherent(struct device *dev, size_t size, void *vaddr,
			       dma_addr_t dma_addr, struct dma_attrs *attrs);

/*
 * Whatever kernel you are using, if it is a x86_64 kernel,
 * this functions are empty. They are only needed for x86_32
 */
#define dma_alloc_from_coherent(dev, size, handle, ret)		(0)
#define dma_release_from_coherent(dev, order, vaddr)		(0)
#define dma_mmap_from_coherent(dev, vma, vaddr, order, ret)	(0)

static inline void *
dma_alloc_attrs(struct device *dev, size_t size, dma_addr_t *dma_handle,
		gfp_t gfp, struct dma_attrs *attrs)
{
	struct dma_map_ops *ops = get_dma_ops(dev);
	void *memory;

	gfp &= ~(__GFP_DMA | __GFP_HIGHMEM | __GFP_DMA32);

	/* It is a no-op */
	if (dma_alloc_from_coherent(dev, size, dma_handle, &memory))
		return memory;

	/*
	 * For Lego, this should not happen.
	 */
	if (!dev) {
		WARN_ON_ONCE(1);
		dev = &x86_dma_fallback_dev;
	}

	if (!is_device_dma_capable(dev))
		return NULL;

	if (!ops->alloc)
		return NULL;

	memory = ops->alloc(dev, size, dma_handle,
			    dma_alloc_coherent_gfp_flags(dev, gfp), attrs);

	return memory;
}

static inline void dma_free_attrs(struct device *dev, size_t size,
				  void *vaddr, dma_addr_t bus,
				  struct dma_attrs *attrs)
{
	struct dma_map_ops *ops = get_dma_ops(dev);

	/* It is a no-op */
	if (dma_release_from_coherent(dev, get_order(size), vaddr))
		return;

	if (ops->free)
		ops->free(dev, size, vaddr, bus, attrs);
}

#define dma_alloc_noncoherent(d, s, h, f)	dma_alloc_coherent(d, s, h, f)
#define dma_free_noncoherent(d, s, v, h)	dma_free_coherent(d, s, v, h)

#define dma_alloc_coherent(d,s,h,f)		dma_alloc_attrs(d,s,h,f,NULL)
#define dma_free_coherent(d,s,c,h)		dma_free_attrs(d,s,c,h,NULL)

static inline dma_addr_t dma_map_single_attrs(struct device *dev, void *ptr,
					      size_t size,
					      enum dma_data_direction dir,
					      struct dma_attrs *attrs)
{
	struct dma_map_ops *ops = get_dma_ops(dev);
	dma_addr_t addr;

	BUG_ON(!valid_dma_direction(dir));
	addr = ops->map_page(dev, virt_to_page(ptr),
			     (unsigned long)ptr & ~PAGE_MASK, size,
			     dir, attrs);
	return addr;
}

static inline void dma_unmap_single_attrs(struct device *dev, dma_addr_t addr,
					  size_t size,
					  enum dma_data_direction dir,
					  struct dma_attrs *attrs)
{
	struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->unmap_page)
		ops->unmap_page(dev, addr, size, dir, attrs);
}

static inline int dma_map_sg_attrs(struct device *dev, struct scatterlist *sg,
				   int nents, enum dma_data_direction dir,
				   struct dma_attrs *attrs)
{
	struct dma_map_ops *ops = get_dma_ops(dev);
	int ents;

	BUG_ON(!valid_dma_direction(dir));
	ents = ops->map_sg(dev, sg, nents, dir, attrs);

	return ents;
}

static inline void dma_unmap_sg_attrs(struct device *dev, struct scatterlist *sg,
				      int nents, enum dma_data_direction dir,
				      struct dma_attrs *attrs)
{
	struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->unmap_sg)
		ops->unmap_sg(dev, sg, nents, dir, attrs);
}

static inline dma_addr_t dma_map_page(struct device *dev, struct page *page,
				      size_t offset, size_t size,
				      enum dma_data_direction dir)
{
	struct dma_map_ops *ops = get_dma_ops(dev);
	dma_addr_t addr;

	BUG_ON(!valid_dma_direction(dir));
	addr = ops->map_page(dev, page, offset, size, dir, NULL);

	return addr;
}

static inline void dma_unmap_page(struct device *dev, dma_addr_t addr,
				  size_t size, enum dma_data_direction dir)
{
	struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->unmap_page)
		ops->unmap_page(dev, addr, size, dir, NULL);
}

static inline void dma_sync_single_for_cpu(struct device *dev, dma_addr_t addr,
					   size_t size,
					   enum dma_data_direction dir)
{
	struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_single_for_cpu)
		ops->sync_single_for_cpu(dev, addr, size, dir);
}

static inline void dma_sync_single_for_device(struct device *dev,
					      dma_addr_t addr, size_t size,
					      enum dma_data_direction dir)
{
	struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_single_for_device)
		ops->sync_single_for_device(dev, addr, size, dir);
}

static inline void dma_sync_single_range_for_cpu(struct device *dev,
						 dma_addr_t addr,
						 unsigned long offset,
						 size_t size,
						 enum dma_data_direction dir)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_single_for_cpu)
		ops->sync_single_for_cpu(dev, addr + offset, size, dir);
}

static inline void dma_sync_single_range_for_device(struct device *dev,
						    dma_addr_t addr,
						    unsigned long offset,
						    size_t size,
						    enum dma_data_direction dir)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_single_for_device)
		ops->sync_single_for_device(dev, addr + offset, size, dir);
}

static inline void
dma_sync_sg_for_cpu(struct device *dev, struct scatterlist *sg,
		    int nelems, enum dma_data_direction dir)
{
	struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_sg_for_cpu)
		ops->sync_sg_for_cpu(dev, sg, nelems, dir);
}

static inline void
dma_sync_sg_for_device(struct device *dev, struct scatterlist *sg,
		       int nelems, enum dma_data_direction dir)
{
	struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_sg_for_device)
		ops->sync_sg_for_device(dev, sg, nelems, dir);
}

#define dma_map_single(d, a, s, r)		dma_map_single_attrs(d, a, s, r, NULL)
#define dma_unmap_single(d, a, s, r)		dma_unmap_single_attrs(d, a, s, r, NULL)
#define dma_map_sg(d, s, n, r)			dma_map_sg_attrs(d, s, n, r, NULL)
#define dma_unmap_sg(d, s, n, r)		dma_unmap_sg_attrs(d, s, n, r, NULL)

extern int dma_common_mmap(struct device *dev, struct vm_area_struct *vma,
			   void *cpu_addr, dma_addr_t dma_addr, size_t size);

/**
 * dma_mmap_attrs - map a coherent DMA allocation into user space
 * @dev: valid struct device pointer, or NULL for ISA and EISA-like devices
 * @vma: vm_area_struct describing requested user mapping
 * @cpu_addr: kernel CPU-view address returned from dma_alloc_attrs
 * @handle: device-view address returned from dma_alloc_attrs
 * @size: size of memory originally requested in dma_alloc_attrs
 * @attrs: attributes of mapping properties requested in dma_alloc_attrs
 *
 * Map a coherent DMA buffer previously allocated by dma_alloc_attrs
 * into user space.  The coherent DMA buffer must not be freed by the
 * driver until the user space mapping has been released.
 */
static inline int
dma_mmap_attrs(struct device *dev, struct vm_area_struct *vma, void *cpu_addr,
	       dma_addr_t dma_addr, size_t size, struct dma_attrs *attrs)
{
	struct dma_map_ops *ops = get_dma_ops(dev);
	BUG_ON(!ops);
	if (ops->mmap)
		return ops->mmap(dev, vma, cpu_addr, dma_addr, size, attrs);
	return dma_common_mmap(dev, vma, cpu_addr, dma_addr, size);
}

#define dma_mmap_coherent(d, v, c, h, s)	dma_mmap_attrs(d, v, c, h, s, NULL)

#endif /* _ASM_X86_DMA_MAPPING_H_ */
