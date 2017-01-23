/*
 * Copyright (c) 2016 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_DMA_MAPPING_H_
#define _LEGO_DMA_MAPPING_H_

#include <lego/sizes.h>
#include <lego/string.h>
#include <lego/pci.h>
#include <lego/err.h>
#include <lego/bug.h>
#include <lego/types.h>
#include <lego/mm.h>
#include <lego/scatterlist.h>

enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};

/**
 * List of possible attributes associated with a DMA mapping. The semantics
 * of each attribute should be defined in Documentation/DMA-attributes.txt.
 *
 * DMA_ATTR_WRITE_BARRIER: DMA to a memory region with this attribute
 * forces all pending DMA writes to complete.
 */
#define DMA_ATTR_WRITE_BARRIER		(1UL << 0)
/*
 * DMA_ATTR_WEAK_ORDERING: Specifies that reads and writes to the mapping
 * may be weakly ordered, that is that reads and writes may pass each other.
 */
#define DMA_ATTR_WEAK_ORDERING		(1UL << 1)
/*
 * DMA_ATTR_WRITE_COMBINE: Specifies that writes to the mapping may be
 * buffered to improve performance.
 */
#define DMA_ATTR_WRITE_COMBINE		(1UL << 2)
/*
 * DMA_ATTR_NON_CONSISTENT: Lets the platform to choose to return either
 * consistent or non-consistent memory as it sees fit.
 */
#define DMA_ATTR_NON_CONSISTENT		(1UL << 3)
/*
 * DMA_ATTR_NO_KERNEL_MAPPING: Lets the platform to avoid creating a kernel
 * virtual mapping for the allocated buffer.
 */
#define DMA_ATTR_NO_KERNEL_MAPPING	(1UL << 4)
/*
 * DMA_ATTR_SKIP_CPU_SYNC: Allows platform code to skip synchronization of
 * the CPU cache for the given buffer assuming that it has been already
 * transferred to 'device' domain.
 */
#define DMA_ATTR_SKIP_CPU_SYNC		(1UL << 5)
/*
 * DMA_ATTR_FORCE_CONTIGUOUS: Forces contiguous allocation of the buffer
 * in physical memory.
 */
#define DMA_ATTR_FORCE_CONTIGUOUS	(1UL << 6)
/*
 * DMA_ATTR_ALLOC_SINGLE_PAGES: This is a hint to the DMA-mapping subsystem
 * that it's probably not worth the time to try to allocate memory to in a way
 * that gives better TLB efficiency.
 */
#define DMA_ATTR_ALLOC_SINGLE_PAGES	(1UL << 7)

/*
 * A dma_addr_t can hold any valid DMA or bus address for the platform.
 * It can be given to a device to use as a DMA source or target.  A CPU cannot
 * reference a dma_addr_t directly because there may be translation between
 * its physical address space and the bus address space.
 */
struct dma_map_ops {
	void* (*alloc)(struct pci_dev *pcid, size_t size,
				dma_addr_t *dma_handle, gfp_t gfp,
				unsigned long attrs);
	void (*free)(struct pci_dev *pcid, size_t size,
			      void *vaddr, dma_addr_t dma_handle,
			      unsigned long attrs);
	int (*mmap)(struct pci_dev *, struct vm_area_struct *,
			  void *, dma_addr_t, size_t,
			  unsigned long attrs);

	dma_addr_t (*map_page)(struct pci_dev *pcid, struct page *page,
			       unsigned long offset, size_t size,
			       enum dma_data_direction dir,
			       unsigned long attrs);
	void (*unmap_page)(struct pci_dev *pcid, dma_addr_t dma_handle,
			   size_t size, enum dma_data_direction dir,
			   unsigned long attrs);
	int (*map_sg)(struct pci_dev *pcid, struct scatterlist *sg,
			int nents, enum dma_data_direction dir,
			unsigned long attrs);
	void (*sync_single_for_cpu)(struct pci_dev *pcid,
			dma_addr_t dma_handle, size_t size,
			enum dma_data_direction dir);
	void (*sync_single_for_device)(struct pci_dev *pcid,
			dma_addr_t dma_handle, size_t size,
			enum dma_data_direction dir);
	int (*mapping_error)(struct pci_dev *pcid, dma_addr_t dma_addr);
	int (*dma_supported)(struct pci_dev *pcid, u64 mask);
	int (*set_dma_mask)(struct pci_dev *pcid, u64 mask);
#ifdef ARCH_HAS_DMA_GET_REQUIRED_MASK
	u64 (*get_required_mask)(struct pci_dev *pcid);
#endif
	int is_phys;
};

extern struct dma_map_ops dma_noop_ops;

#define DMA_BIT_MASK(n)	(((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))

#define DMA_MASK_NONE	0x0ULL

static inline int valid_dma_direction(int dma_direction)
{
	return ((dma_direction == DMA_BIDIRECTIONAL) ||
		(dma_direction == DMA_TO_DEVICE) ||
		(dma_direction == DMA_FROM_DEVICE));
}

static inline int is_device_dma_capable(struct pci_dev *pcid)
{
	return pcid->dma_mask != NULL && *pcid->dma_mask != DMA_MASK_NONE;
}

/*
 * These three functions are only for dma allocator.
 * Don't use them in device drivers.
 */
int dma_alloc_from_coherent(struct pci_dev *pcid, ssize_t size,
				       dma_addr_t *dma_handle, void **ret);
int dma_release_from_coherent(struct pci_dev *pcid, int order, void *vaddr);

int dma_mmap_from_coherent(struct pci_dev *pcid, struct vm_area_struct *vma,
			    void *cpu_addr, size_t size, int *ret);

#include <asm/dma-mapping.h>

static inline dma_addr_t dma_map_single_attrs(struct pci_dev *pcid, void *ptr,
					      size_t size,
					      enum dma_data_direction dir,
					      unsigned long attrs)
{
	struct dma_map_ops *ops = get_dma_ops(pcid);
	dma_addr_t addr;

	BUG_ON(!valid_dma_direction(dir));
	addr = ops->map_page(pcid, virt_to_page(ptr),
			     offset_in_page(ptr), size,
			     dir, attrs);
	return addr;
}

static inline void dma_unmap_single_attrs(struct pci_dev *pcid, dma_addr_t addr,
					  size_t size,
					  enum dma_data_direction dir,
					  unsigned long attrs)
{
	struct dma_map_ops *ops = get_dma_ops(pcid);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->unmap_page)
		ops->unmap_page(pcid, addr, size, dir, attrs);
}

static inline dma_addr_t dma_map_page(struct pci_dev *pcid, struct page *page,
				      size_t offset, size_t size,
				      enum dma_data_direction dir)
{
	struct dma_map_ops *ops = get_dma_ops(pcid);
	dma_addr_t addr;

	BUG_ON(!valid_dma_direction(dir));
	addr = ops->map_page(pcid, page, offset, size, dir, 0);

	return addr;
}

static inline void dma_unmap_page(struct pci_dev *pcid, dma_addr_t addr,
				  size_t size, enum dma_data_direction dir)
{
	struct dma_map_ops *ops = get_dma_ops(pcid);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->unmap_page)
		ops->unmap_page(pcid, addr, size, dir, 0);
}

static inline void dma_sync_single_for_cpu(struct pci_dev *pcid, dma_addr_t addr,
					   size_t size,
					   enum dma_data_direction dir)
{
	struct dma_map_ops *ops = get_dma_ops(pcid);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_single_for_cpu)
		ops->sync_single_for_cpu(pcid, addr, size, dir);
}

static inline void dma_sync_single_for_device(struct pci_dev *pcid,
					      dma_addr_t addr, size_t size,
					      enum dma_data_direction dir)
{
	struct dma_map_ops *ops = get_dma_ops(pcid);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_single_for_device)
		ops->sync_single_for_device(pcid, addr, size, dir);
}

static inline void dma_sync_single_range_for_cpu(struct pci_dev *pcid,
						 dma_addr_t addr,
						 unsigned long offset,
						 size_t size,
						 enum dma_data_direction dir)
{
	const struct dma_map_ops *ops = get_dma_ops(pcid);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_single_for_cpu)
		ops->sync_single_for_cpu(pcid, addr + offset, size, dir);
}

static inline void dma_sync_single_range_for_device(struct pci_dev *pcid,
						    dma_addr_t addr,
						    unsigned long offset,
						    size_t size,
						    enum dma_data_direction dir)
{
	const struct dma_map_ops *ops = get_dma_ops(pcid);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_single_for_device)
		ops->sync_single_for_device(pcid, addr + offset, size, dir);
}

#define dma_map_single(d, a, s, r) dma_map_single_attrs(d, a, s, r, 0)
#define dma_unmap_single(d, a, s, r) dma_unmap_single_attrs(d, a, s, r, 0)

extern int dma_common_mmap(struct pci_dev *pcid, struct vm_area_struct *vma,
			   void *cpu_addr, dma_addr_t dma_addr, size_t size);

void *dma_common_contiguous_remap(struct page *page, size_t size,
			unsigned long vm_flags,
			pgprot_t prot, const void *caller);

void *dma_common_pages_remap(struct page **pages, size_t size,
			unsigned long vm_flags, pgprot_t prot,
			const void *caller);
void dma_common_free_remap(void *cpu_addr, size_t size, unsigned long vm_flags);

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
dma_mmap_attrs(struct pci_dev *pcid, struct vm_area_struct *vma, void *cpu_addr,
	       dma_addr_t dma_addr, size_t size, unsigned long attrs)
{
	struct dma_map_ops *ops = get_dma_ops(pcid);
	BUG_ON(!ops);
	if (ops->mmap)
		return ops->mmap(pcid, vma, cpu_addr, dma_addr, size, attrs);
	return dma_common_mmap(pcid, vma, cpu_addr, dma_addr, size);
}

#define dma_mmap_coherent(d, v, c, h, s) dma_mmap_attrs(d, v, c, h, s, 0)

#ifndef arch_dma_alloc_attrs
#define arch_dma_alloc_attrs(pcid, flag)	(true)
#endif

void dma_generic_free_coherent(struct pci_dev *pcid, size_t size, void *vaddr,
			       dma_addr_t dma_addr, unsigned long attrs);
void dma_generic_free_coherent(struct pci_dev *pcid, size_t size, void *vaddr,
			       dma_addr_t dma_addr, unsigned long attrs);
int nommu_map_sg(struct pci_dev *hwdev, struct scatterlist *sg,
                        int nents, enum dma_data_direction dir,
                        unsigned long attrs);

static inline void *dma_alloc_attrs(struct pci_dev *pcid, size_t size,
				       dma_addr_t *dma_handle, gfp_t flag,
				       unsigned long attrs)
{
	//struct dma_map_ops *ops = get_dma_ops(pcid);
	void *cpu_addr;

	//BUG_ON(!ops);

//	if (dma_alloc_from_coherent(pcid, size, dma_handle, &cpu_addr))
//		return cpu_addr;

	if (!arch_dma_alloc_attrs(&pcid, &flag)) {
		pr_debug("archdma return NULL\n");
		return NULL;
	}
	//pr_debug("%s opsalloc\n", __func__);
//	if (!ops->alloc)
//		return NULL;

	//pr_debug("%s before opsalloc\n", __func__);
//	cpu_addr = ops->alloc(pcid, size, dma_handle, flag, attrs);
	cpu_addr = dma_generic_alloc_coherent(pcid, size, dma_handle, flag, attrs);
//	pr_debug("%s ops %p pcid %p size %lx allocated dmaaddr %lx\n", __func__, ops, pcid, size, cpu_addr);
	return cpu_addr;
}

static inline int dma_map_sg_attrs(struct pci_dev *dev, struct scatterlist *sg,
                                   int nents, enum dma_data_direction dir,
                                   unsigned long attrs)
{
        //struct dma_map_ops *ops = get_dma_ops(dev);
        //int i;
	int ents;
        //struct scatterlist *s;

        //for_each_sg(sg, s, nents, i)
          //     kmemcheck_mark_initialized(sg_virt(s), s->length);
        BUG_ON(!valid_dma_direction(dir));
        ents = nommu_map_sg(dev, sg, nents, dir, attrs);
        //ents = ops->map_sg(dev, sg, nents, dir, attrs);
        //debug_dma_map_sg(dev, sg, nents, ents, dir);

        return ents;
}

#define dma_map_sg(d, s, n, r) dma_map_sg_attrs(d, s, n, r, NULL)

static inline void dma_free_attrs(struct pci_dev *pcid, size_t size,
				     void *cpu_addr, dma_addr_t dma_handle,
				     unsigned long attrs)
{
	struct dma_map_ops *ops = get_dma_ops(pcid);

	BUG_ON(!ops);
//	WARN_ON(irqs_disabled());

	if (dma_release_from_coherent(pcid, get_order(size), cpu_addr))
		return;

//	if (!ops->free || !cpu_addr)
//		return;

//	ops->free(pcid, size, cpu_addr, dma_handle, attrs);
	dma_generic_free_coherent(pcid, size, cpu_addr, dma_handle, attrs);
}

static inline void *dma_alloc_coherent(struct pci_dev *pcid, size_t size,
		dma_addr_t *dma_handle, gfp_t flag)
{
	return dma_alloc_attrs(pcid, size, dma_handle, flag, 0);
}

static inline void dma_free_coherent(struct pci_dev *pcid, size_t size,
		void *cpu_addr, dma_addr_t dma_handle)
{
	return dma_free_attrs(pcid, size, cpu_addr, dma_handle, 0);
}

static inline void *dma_alloc_noncoherent(struct pci_dev *pcid, size_t size,
		dma_addr_t *dma_handle, gfp_t gfp)
{
	return dma_alloc_attrs(pcid, size, dma_handle, gfp,
			       DMA_ATTR_NON_CONSISTENT);
}

static inline void dma_free_noncoherent(struct pci_dev *pcid, size_t size,
		void *cpu_addr, dma_addr_t dma_handle)
{
	dma_free_attrs(pcid, size, cpu_addr, dma_handle,
		       DMA_ATTR_NON_CONSISTENT);
}

static inline int dma_mapping_error(struct pci_dev *pcid, dma_addr_t dma_addr)
{

	if (get_dma_ops(pcid)->mapping_error)
		return get_dma_ops(pcid)->mapping_error(pcid, dma_addr);

#ifdef DMA_ERROR_CODE
	return dma_addr == DMA_ERROR_CODE;
#else
	return 0;
#endif
}

#ifndef HAVE_ARCH_DMA_SUPPORTED
static inline int dma_supported(struct pci_dev *pcid, u64 mask)
{
	struct dma_map_ops *ops = get_dma_ops(pcid);

	if (!ops)
		return 0;
	if (!ops->dma_supported)
		return 1;
	return ops->dma_supported(pcid, mask);
}
#endif

#ifndef HAVE_ARCH_DMA_SET_MASK
static inline int dma_set_mask(struct pci_dev *pcid, u64 mask)
{
	struct dma_map_ops *ops = get_dma_ops(pcid);

	if (ops->set_dma_mask)
		return ops->set_dma_mask(pcid, mask);

	if (!pcid->dma_mask || !dma_supported(pcid, mask))
		return -EIO;
	*pcid->dma_mask = mask;
	return 0;
}
#endif

static inline u64 dma_get_mask(struct pci_dev *pcid)
{
	if (pcid && pcid->dma_mask && *pcid->dma_mask)
		return *pcid->dma_mask;
	return DMA_BIT_MASK(32);
}

#ifdef CONFIG_ARCH_HAS_DMA_SET_COHERENT_MASK
int dma_set_coherent_mask(struct pci_dev *pcid, u64 mask);
#else
static inline int dma_set_coherent_mask(struct pci_dev *pcid, u64 mask)
{
	if (!dma_supported(pcid, mask))
		return -EIO;
	pcid->coherent_dma_mask = mask;
	return 0;
}
#endif

/*
 * Set both the DMA mask and the coherent DMA mask to the same thing.
 * Note that we don't check the return value from dma_set_coherent_mask()
 * as the DMA API guarantees that the coherent DMA mask can be set to
 * the same or smaller than the streaming DMA mask.
 */
static inline int dma_set_mask_and_coherent(struct pci_dev *pcid, u64 mask)
{
	int rc = dma_set_mask(pcid, mask);
	if (rc == 0)
		dma_set_coherent_mask(pcid, mask);
	return rc;
}

/*
 * Similar to the above, except it deals with the case where the device
 * does not have pcid->dma_mask appropriately setup.
 */
static inline int dma_coerce_mask_and_coherent(struct pci_dev *pcid, u64 mask)
{
	pcid->dma_mask = &pcid->coherent_dma_mask;
	return dma_set_mask_and_coherent(pcid, mask);
}

extern u64 dma_get_required_mask(struct pci_dev *pcid);

#if 0
#ifndef arch_setup_dma_ops
static inline void arch_setup_dma_ops(struct pci_dev *pcid, u64 dma_base,
				      u64 size, const struct iommu_ops *iommu,
				      bool coherent) { }
#endif

#ifndef arch_teardown_dma_ops
static inline void arch_teardown_dma_ops(struct pci_dev *pcid) { }
#endif
#endif

#ifndef dma_max_pfn
static inline unsigned long dma_max_pfn(struct pci_dev *pcid)
{
	return *pcid->dma_mask >> PAGE_SHIFT;
}
#endif

static inline void *dma_zalloc_coherent(struct pci_dev *pcid, size_t size,
					dma_addr_t *dma_handle, gfp_t flag)
{
	void *ret = dma_alloc_coherent(pcid, size, dma_handle,
				       flag | __GFP_ZERO);
	return ret;
}

static inline int dma_get_cache_alignment(void)
{
#ifdef ARCH_DMA_MINALIGN
	return ARCH_DMA_MINALIGN;
#endif
	return 1;
}

/* flags for the coherent memory api */
#define	DMA_MEMORY_MAP			0x01
#define DMA_MEMORY_IO			0x02
#define DMA_MEMORY_INCLUDES_CHILDREN	0x04
#define DMA_MEMORY_EXCLUSIVE		0x08

int dma_declare_coherent_memory(struct pci_dev *pcid, phys_addr_t phys_addr,
				dma_addr_t device_addr, size_t size, int flags);
void dma_release_declared_memory(struct pci_dev *pcid);
void *dma_mark_declared_memory_occupied(struct pci_dev *pcid,
					dma_addr_t device_addr, size_t size);

/*
 * Managed DMA API
 */
extern void *dmam_alloc_coherent(struct pci_dev *pcid, size_t size,
				 dma_addr_t *dma_handle, gfp_t gfp);
extern void dmam_free_coherent(struct pci_dev *pcid, size_t size, void *vaddr,
			       dma_addr_t dma_handle);
extern void *dmam_alloc_noncoherent(struct pci_dev *pcid, size_t size,
				    dma_addr_t *dma_handle, gfp_t gfp);
extern void dmam_free_noncoherent(struct pci_dev *pcid, size_t size, void *vaddr,
				  dma_addr_t dma_handle);
#ifdef CONFIG_HAVE_GENERIC_DMA_COHERENT
extern int dmam_declare_coherent_memory(struct pci_dev *pcid,
					phys_addr_t phys_addr,
					dma_addr_t device_addr, size_t size,
					int flags);
extern void dmam_release_declared_memory(struct pci_dev *pcid);
#else /* CONFIG_HAVE_GENERIC_DMA_COHERENT */
static inline int dmam_declare_coherent_memory(struct pci_dev *pcid,
				phys_addr_t phys_addr, dma_addr_t device_addr,
				size_t size, gfp_t gfp)
{
	return 0;
}

static inline void dmam_release_declared_memory(struct pci_dev *pcid)
{
}
#endif /* CONFIG_HAVE_GENERIC_DMA_COHERENT */

static inline void *dma_alloc_wc(struct pci_dev *pcid, size_t size,
				 dma_addr_t *dma_addr, gfp_t gfp)
{
	return dma_alloc_attrs(pcid, size, dma_addr, gfp,
			       DMA_ATTR_WRITE_COMBINE);
}
#ifndef dma_alloc_writecombine
#define dma_alloc_writecombine dma_alloc_wc
#endif

static inline void dma_free_wc(struct pci_dev *pcid, size_t size,
			       void *cpu_addr, dma_addr_t dma_addr)
{
	return dma_free_attrs(pcid, size, cpu_addr, dma_addr,
			      DMA_ATTR_WRITE_COMBINE);
}
#ifndef dma_free_writecombine
#define dma_free_writecombine dma_free_wc
#endif

static inline int dma_mmap_wc(struct pci_dev *pcid,
			      struct vm_area_struct *vma,
			      void *cpu_addr, dma_addr_t dma_addr,
			      size_t size)
{
	return dma_mmap_attrs(pcid, vma, cpu_addr, dma_addr, size,
			      DMA_ATTR_WRITE_COMBINE);
}
#ifndef dma_mmap_writecombine
#define dma_mmap_writecombine dma_mmap_wc
#endif

#if defined(CONFIG_NEED_DMA_MAP_STATE) || defined(CONFIG_DMA_API_DEBUG)
#define DEFINE_DMA_UNMAP_ADDR(ADDR_NAME)        dma_addr_t ADDR_NAME
#define DEFINE_DMA_UNMAP_LEN(LEN_NAME)          __u32 LEN_NAME
#define dma_unmap_addr(PTR, ADDR_NAME)           ((PTR)->ADDR_NAME)
#define dma_unmap_addr_set(PTR, ADDR_NAME, VAL)  (((PTR)->ADDR_NAME) = (VAL))
#define dma_unmap_len(PTR, LEN_NAME)             ((PTR)->LEN_NAME)
#define dma_unmap_len_set(PTR, LEN_NAME, VAL)    (((PTR)->LEN_NAME) = (VAL))
#else
#define DEFINE_DMA_UNMAP_ADDR(ADDR_NAME)
#define DEFINE_DMA_UNMAP_LEN(LEN_NAME)
#define dma_unmap_addr(PTR, ADDR_NAME)           (0)
#define dma_unmap_addr_set(PTR, ADDR_NAME, VAL)  do { } while (0)
#define dma_unmap_len(PTR, LEN_NAME)             (0)
#define dma_unmap_len_set(PTR, LEN_NAME, VAL)    do { } while (0)
#endif

extern struct dma_map_ops nommu_dma_ops;

#endif /* _LEGO_DMA_MAPPING_H_ */
