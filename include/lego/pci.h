#ifndef _LEGO_PCI_H_
#define _LEGO_PCI_H_

#include <lego/types.h>
#include <lego/pci_regs.h>

#if 0
/*
 * The PCI interface treats multi-function devices as independent
 * devices.  The slot/function address of each device is encoded
 * in a single byte as follows:
 *
 *	7:3 = slot
 *	2:0 = function
 */
#define PCI_DEVFN(slot, func)	((((slot) & 0x1f) << 3) | ((func) & 0x07))
#define PCI_SLOT(devfn)		(((devfn) >> 3) & 0x1f)
#define PCI_FUNC(devfn)		((devfn) & 0x07)

/* Ioctls for /proc/bus/pci/X/Y nodes. */
#define PCIIOC_BASE		('P' << 24 | 'C' << 16 | 'I' << 8)
#define PCIIOC_CONTROLLER	(PCIIOC_BASE | 0x00)	/* Get controller for PCI device. */
#define PCIIOC_MMAP_IS_IO	(PCIIOC_BASE | 0x01)	/* Set mmap state to I/O space. */
#define PCIIOC_MMAP_IS_MEM	(PCIIOC_BASE | 0x02)	/* Set mmap state to MEM space. */
#define PCIIOC_WRITE_COMBINE	(PCIIOC_BASE | 0x03)	/* Enable/disable write-combining. */
#endif
;

// PCI subsystem interface
enum pci_res { 
	pci_res_bus = 0,
	pci_res_mem = 1,
	pci_res_io = 2,
	pci_res_max = 3
};

struct pci_bus;

struct pci_dev {
	struct pci_bus 		*bus;	// Primary bus for bridges

	u64			dev;
	u32			func;

	u32			dev_id;
	u32			dev_class;

	unsigned int		msi_enabled:1;
	unsigned int		msix_enabled:1;
	u8			msi_cap;        /* MSI capability offset */
	u8      	        msix_cap;       /* MSI-X capability offset */
#ifdef CONFIG_PCI_MSI
	struct list_head	msi_list;
#endif

	/*
	 *  For PCI devices, the region numbers are assigned this way:
	 *
	 *      0-5     standard PCI regions
	 *      6       expansion ROM
	 *      7-10    bridges: address space assigned to buses behind the bridge
	 */
	u32			reg_base[11];
	u32			reg_size[11];
	u8			irq_line;

	u64			*dma_mask;
	u64			coherent_dma_mask;
	struct dma_coherent_mem	*dma_mem;

	unsigned int		irq;
	unsigned int		error_state;

	void			*driver_data;
	void			*priv;
};

#define pci_resource_start(dev, bar)    ((dev)->reg_base[(bar)])
#define pci_resource_len(dev, bar)    ((dev)->reg_size[(bar)])
#define pci_resource_end(dev, bar)      ((dev)->reg_base[(bar)] + (dev)->reg_size[(bar)])

struct pci_bus {
	struct pci_dev *parent_bridge;
	u32 busno;
};

int  pci_init(void);
void pci_func_enable(struct pci_dev *f);

#ifdef CONFIG_E1000
int pci_func_attach_E1000(struct pci_dev *f);

int pci_transmit_packet(const void * src,size_t n);
int pci_receive_packet(void * dst);
#endif

#ifdef CONFIG_INFINIBAND
int mlx4_init_one(struct pci_dev *f);
#endif

u32 pci_conf_read(struct pci_dev *f, u32 off, int len);
void pci_conf_write(struct pci_dev *f, u32 off, u32 v, int len);

typedef unsigned int __bitwise pci_channel_state_t;

enum pci_channel_state {
        /* I/O channel is in normal state */
        pci_channel_io_normal = (__force pci_channel_state_t) 1,

        /* I/O to channel is blocked */
        pci_channel_io_frozen = (__force pci_channel_state_t) 2,

        /* PCI card is dead */
        pci_channel_io_perm_failure = (__force pci_channel_state_t) 3,
};

static inline int pci_channel_offline(struct pci_dev *pcif)
{
        return (pcif->error_state != pci_channel_io_normal);
}

/* This defines the direction arg to the DMA mapping routines. */
#define PCI_DMA_BIDIRECTIONAL   0
#define PCI_DMA_TODEVICE        1
#define PCI_DMA_FROMDEVICE      2
#define PCI_DMA_NONE            3

struct msix_entry {
        u32     vector; /* kernel uses to write allocated vector */
        u16     entry;  /* driver uses to specify entry, OS writes */
};

#endif
