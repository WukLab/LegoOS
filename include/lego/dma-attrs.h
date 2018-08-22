/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_DMA_ATTRS_H_
#define _LEGO_DMA_ATTRS_H_

#include <lego/bitmap.h>
#include <lego/bitops.h>
#include <lego/kernel.h>

/**
 * an enum dma_attr represents an attribute associated with a DMA
 * mapping. The semantics of each attribute should be defined in
 * Documentation/DMA-attributes.txt.
 */
enum dma_attr {
	DMA_ATTR_WRITE_BARRIER,
	DMA_ATTR_WEAK_ORDERING,
	DMA_ATTR_WRITE_COMBINE,
	DMA_ATTR_NON_CONSISTENT,
	DMA_ATTR_NO_KERNEL_MAPPING,
	DMA_ATTR_SKIP_CPU_SYNC,
	DMA_ATTR_FORCE_CONTIGUOUS,
	DMA_ATTR_MAX,
};

#define __DMA_ATTRS_LONGS BITS_TO_LONGS(DMA_ATTR_MAX)

/**
 * struct dma_attrs - an opaque container for DMA attributes
 * @flags - bitmask representing a collection of enum dma_attr
 */
struct dma_attrs {
	unsigned long flags[__DMA_ATTRS_LONGS];
};

#define DEFINE_DMA_ATTRS(x) 					\
	struct dma_attrs x = {					\
		.flags = { [0 ... __DMA_ATTRS_LONGS-1] = 0 },	\
	}

static inline void init_dma_attrs(struct dma_attrs *attrs)
{
	bitmap_zero(attrs->flags, __DMA_ATTRS_LONGS);
}

#ifdef CONFIG_HAVE_DMA_ATTRS
/**
 * dma_set_attr - set a specific attribute
 * @attr: attribute to set
 * @attrs: struct dma_attrs (may be NULL)
 */
static inline void dma_set_attr(enum dma_attr attr, struct dma_attrs *attrs)
{
	if (attrs == NULL)
		return;
	BUG_ON(attr >= DMA_ATTR_MAX);
	__set_bit(attr, attrs->flags);
}

/**
 * dma_get_attr - check for a specific attribute
 * @attr: attribute to set
 * @attrs: struct dma_attrs (may be NULL)
 */
static inline int dma_get_attr(enum dma_attr attr, struct dma_attrs *attrs)
{
	if (attrs == NULL)
		return 0;
	BUG_ON(attr >= DMA_ATTR_MAX);
	return test_bit(attr, attrs->flags);
}
#else /* !CONFIG_HAVE_DMA_ATTRS */
static inline void dma_set_attr(enum dma_attr attr, struct dma_attrs *attrs)
{
}

static inline int dma_get_attr(enum dma_attr attr, struct dma_attrs *attrs)
{
	return 0;
}
#endif /* CONFIG_HAVE_DMA_ATTRS */

#endif /* _LEGO_DMA_ATTRS_H_ */
