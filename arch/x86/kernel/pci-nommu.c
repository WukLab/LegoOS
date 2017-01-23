/* Fallback functions when the main IOMMU code is not compiled in. This
   code is roughly equivalent to i386. */
#include <lego/dma-mapping.h>
#include <lego/string.h>
#include <lego/gfp.h>
#include <lego/pci.h>
#include <lego/mm.h>
#include <lego/scatterlist.h>

#include <asm/processor.h>
#include <asm/dma.h>

static int
check_addr(char *name, struct pci_dev *hwdev, dma_addr_t bus, size_t size)
{
	if (hwdev && !dma_capable(hwdev, bus, size)) {
		if (*hwdev->dma_mask >= DMA_BIT_MASK(32))
			printk(KERN_ERR
			    "nommu_%s: overflow %Lx+%zu of device mask %Lx\n",
				name, (long long)bus, size,
				(long long)*hwdev->dma_mask);
		return 0;
	}
	return 1;
}

static dma_addr_t nommu_map_page(struct pci_dev *dev, struct page *page,
				 unsigned long offset, size_t size,
				 enum dma_data_direction dir,
				 unsigned long attrs)
{
	dma_addr_t bus = page_to_phys(page) + offset;
/*
	pr_debug("%s dev %p page %p bus %lx offset %lx\n",
			__func__, dev, page, bus, offset); 
*/
	WARN_ON(size == 0);
	if (!check_addr("map_single", dev, bus, size))
		return DMA_ERROR_CODE;
	flush_write_buffers();
	return bus;
}

/* Map a set of buffers described by scatterlist in streaming
 * mode for DMA.  This is the scatter-gather version of the
 * above pci_map_single interface.  Here the scatter gather list
 * elements are each tagged with the appropriate dma address
 * and length.  They are obtained via sg_dma_{address,length}(SG).
 *
 * NOTE: An implementation may be able to use a smaller number of
 *       DMA address/length pairs than there are SG table elements.
 *       (for example via virtual mapping capabilities)
 *       The routine returns the number of addr/length pairs actually
 *       used, at most nents.
 *
 * Device ownership issues as mentioned above for pci_map_single are
 * the same here.
 */
int nommu_map_sg(struct pci_dev *hwdev, struct scatterlist *sg,
                        int nents, enum dma_data_direction dir,
                        unsigned long attrs)
{
        struct scatterlist *s;
        int i;

        WARN_ON(nents == 0 || sg[0].length == 0);

        for_each_sg(sg, s, nents, i) {
                BUG_ON(!sg_page(s));
                s->dma_address = sg_phys(s);
/*
		pr_debug("%s dev %p, dma_addr %lx length %lx\n", 
				__func__, hwdev, s->dma_address, s->length);
*/
                //if (!check_addr("map_sg", hwdev, s->dma_address, s->length))
                  //      return 0;
                s->dma_length = s->length;
        }
        flush_write_buffers();
         return nents;
}

static void nommu_sync_single_for_device(struct pci_dev *dev,
			dma_addr_t addr, size_t size,
			enum dma_data_direction dir)
{
	flush_write_buffers();
}

struct dma_map_ops nommu_dma_ops = {
	.alloc			= dma_generic_alloc_coherent,
	.free			= dma_generic_free_coherent,
	.map_sg                 = nommu_map_sg,
	.map_page		= nommu_map_page,
	.sync_single_for_device = nommu_sync_single_for_device,
	.is_phys		= 1,
};
