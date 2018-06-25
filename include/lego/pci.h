/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PCI_H_
#define _LEGO_PCI_H_

#include <lego/types.h>
#include <lego/errno.h>
#include <lego/device.h>
#include <lego/pci_ids.h>
#include <lego/pci_regs.h>
#include <lego/spinlock.h>

/* This defines the direction arg to the DMA mapping routines. */
#define PCI_DMA_BIDIRECTIONAL	0
#define PCI_DMA_TODEVICE	1
#define PCI_DMA_FROMDEVICE	2
#define PCI_DMA_NONE		3

/*
 *  For PCI devices, the region numbers are assigned this way:
 */
enum {
	/* #0-5: standard PCI resources */
	PCI_STD_RESOURCES,
	PCI_STD_RESOURCE_END = 5,

	/* #6: expansion ROM resource */
	PCI_ROM_RESOURCE,

	/* device specific resources */
#ifdef CONFIG_PCI_IOV
	PCI_IOV_RESOURCES,
	PCI_IOV_RESOURCE_END = PCI_IOV_RESOURCES + PCI_SRIOV_NUM_BARS - 1,
#endif

	/* resources assigned to buses behind the bridge */
#define PCI_BRIDGE_RESOURCE_NUM 4

	PCI_BRIDGE_RESOURCES,
	PCI_BRIDGE_RESOURCE_END = PCI_BRIDGE_RESOURCES +
				  PCI_BRIDGE_RESOURCE_NUM - 1,

	/* total resources associated with a PCI device */
	PCI_NUM_RESOURCES,

	/* preserve this for compatibility */
	DEVICE_COUNT_RESOURCE = PCI_NUM_RESOURCES,
};

typedef int __bitwise pci_power_t;

#define PCI_D0		((pci_power_t __force) 0)
#define PCI_D1		((pci_power_t __force) 1)
#define PCI_D2		((pci_power_t __force) 2)
#define PCI_D3hot	((pci_power_t __force) 3)
#define PCI_D3cold	((pci_power_t __force) 4)
#define PCI_UNKNOWN	((pci_power_t __force) 5)
#define PCI_POWER_ERROR	((pci_power_t __force) -1)

/* Remember to update this when the list above changes! */
extern const char *pci_power_names[];

static inline const char *pci_power_name(pci_power_t state)
{
	return pci_power_names[1 + (int) state];
}

#define PCI_PM_D2_DELAY		200
#define PCI_PM_D3_WAIT		10
#define PCI_PM_D3COLD_WAIT	100
#define PCI_PM_BUS_WAIT		50

/** The pci_channel state describes connectivity between the CPU and
 *  the pci device.  If some PCI bus between here and the pci device
 *  has crashed or locked up, this info is reflected here.
 */
typedef unsigned int __bitwise pci_channel_state_t;

enum pci_channel_state {
	/* I/O channel is in normal state */
	pci_channel_io_normal = (__force pci_channel_state_t) 1,

	/* I/O to channel is blocked */
	pci_channel_io_frozen = (__force pci_channel_state_t) 2,

	/* PCI card is dead */
	pci_channel_io_perm_failure = (__force pci_channel_state_t) 3,
};

typedef unsigned int __bitwise pcie_reset_state_t;

enum pcie_reset_state {
	/* Reset is NOT asserted (Use to deassert reset) */
	pcie_deassert_reset = (__force pcie_reset_state_t) 1,

	/* Use #PERST to reset PCI-E device */
	pcie_warm_reset = (__force pcie_reset_state_t) 2,

	/* Use PCI-E Hot Reset to reset device */
	pcie_hot_reset = (__force pcie_reset_state_t) 3
};

typedef unsigned short __bitwise pci_dev_flags_t;
enum pci_dev_flags {
	/* INTX_DISABLE in PCI_COMMAND register disables MSI
	 * generation too.
	 */
	PCI_DEV_FLAGS_MSI_INTX_DISABLE_BUG = (__force pci_dev_flags_t) 1,
	/* Device configuration is irrevocably lost if disabled into D3 */
	PCI_DEV_FLAGS_NO_D3 = (__force pci_dev_flags_t) 2,
	/* Provide indication device is assigned by a Virtual Machine Manager */
	PCI_DEV_FLAGS_ASSIGNED = (__force pci_dev_flags_t) 4,
};

enum pci_irq_reroute_variant {
	INTEL_IRQ_REROUTE_VARIANT = 1,
	MAX_IRQ_REROUTE_VARIANTS = 3
};

typedef unsigned short __bitwise pci_bus_flags_t;
enum pci_bus_flags {
	PCI_BUS_FLAGS_NO_MSI   = (__force pci_bus_flags_t) 1,
	PCI_BUS_FLAGS_NO_MMRBC = (__force pci_bus_flags_t) 2,
};

/* Based on the PCI Hotplug Spec, but some values are made up by us */
enum pci_bus_speed {
	PCI_SPEED_33MHz			= 0x00,
	PCI_SPEED_66MHz			= 0x01,
	PCI_SPEED_66MHz_PCIX		= 0x02,
	PCI_SPEED_100MHz_PCIX		= 0x03,
	PCI_SPEED_133MHz_PCIX		= 0x04,
	PCI_SPEED_66MHz_PCIX_ECC	= 0x05,
	PCI_SPEED_100MHz_PCIX_ECC	= 0x06,
	PCI_SPEED_133MHz_PCIX_ECC	= 0x07,
	PCI_SPEED_66MHz_PCIX_266	= 0x09,
	PCI_SPEED_100MHz_PCIX_266	= 0x0a,
	PCI_SPEED_133MHz_PCIX_266	= 0x0b,
	AGP_UNKNOWN			= 0x0c,
	AGP_1X				= 0x0d,
	AGP_2X				= 0x0e,
	AGP_4X				= 0x0f,
	AGP_8X				= 0x10,
	PCI_SPEED_66MHz_PCIX_533	= 0x11,
	PCI_SPEED_100MHz_PCIX_533	= 0x12,
	PCI_SPEED_133MHz_PCIX_533	= 0x13,
	PCIE_SPEED_2_5GT		= 0x14,
	PCIE_SPEED_5_0GT		= 0x15,
	PCIE_SPEED_8_0GT		= 0x16,
	PCI_SPEED_UNKNOWN		= 0xff,
};

struct pci_cap_saved_data {
	char cap_nr;
	unsigned int size;
	u32 data[0];
};

struct pci_cap_saved_state {
	struct hlist_node next;
	struct pci_cap_saved_data cap;
};

// PCI subsystem interface
enum pci_res { 
	pci_res_bus = 0,
	pci_res_mem = 1,
	pci_res_io = 2,
	pci_res_max = 3
};

struct pci_bus;

struct pci_dev {
	struct pci_bus 		*bus;

	unsigned int	devfn;		/* encoded device & function index */
	unsigned short	vendor;
	unsigned short	device;

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
	struct list_head node;		/* node in list of buses */
	struct pci_bus	*parent;	/* parent bus this bridge is on */
	struct list_head children;	/* list of child buses */
	struct list_head devices;	/* list of devices on this bus */
	struct pci_dev	*self;		/* bridge device as seen by parent */

	struct pci_ops	*ops;		/* configuration access functions */

	unsigned char	number;		/* bus number */
	unsigned char	primary;	/* number of primary bridge */
	unsigned char	max_bus_speed;	/* enum pci_bus_speed */
	unsigned char	cur_bus_speed;	/* enum pci_bus_speed */

	char		name[48];
};

/*
 * Returns true if the pci bus is root (behind host-pci bridge),
 * false otherwise
 */
static inline bool pci_is_root_bus(struct pci_bus *pbus)
{
	return !(pbus->parent);
}

#ifdef CONFIG_PCI_MSI
static inline bool pci_dev_msi_enabled(struct pci_dev *pci_dev)
{
	return pci_dev->msi_enabled || pci_dev->msix_enabled;
}
#else
static inline bool pci_dev_msi_enabled(struct pci_dev *pci_dev) { return false; }
#endif

/*
 * Error values that may be returned by PCI functions.
 */
#define PCIBIOS_SUCCESSFUL		0x00
#define PCIBIOS_FUNC_NOT_SUPPORTED	0x81
#define PCIBIOS_BAD_VENDOR_ID		0x83
#define PCIBIOS_DEVICE_NOT_FOUND	0x86
#define PCIBIOS_BAD_REGISTER_NUMBER	0x87
#define PCIBIOS_SET_FAILED		0x88
#define PCIBIOS_BUFFER_TOO_SMALL	0x89

/*
 * Translate above to generic errno for passing back through non-pci.
 */
static inline int pcibios_err_to_errno(int err)
{
	if (err <= PCIBIOS_SUCCESSFUL)
		return err; /* Assume already errno */

	switch (err) {
	case PCIBIOS_FUNC_NOT_SUPPORTED:
		return -ENOENT;
	case PCIBIOS_BAD_VENDOR_ID:
		return -EINVAL;
	case PCIBIOS_DEVICE_NOT_FOUND:
		return -ENODEV;
	case PCIBIOS_BAD_REGISTER_NUMBER:
		return -EFAULT;
	case PCIBIOS_SET_FAILED:
		return -EIO;
	case PCIBIOS_BUFFER_TOO_SMALL:
		return -ENOSPC;
	}

	return -ENOTTY;
}

/* Low-level architecture-dependent routines */

struct pci_ops {
	int (*read)(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 *val);
	int (*write)(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 val);
};

struct pci_bus_region {
	resource_size_t start;
	resource_size_t end;
};

struct pci_dynids {
	spinlock_t lock;            /* protects list, index */
	struct list_head list;      /* for IDs added at runtime */
};

/* ---------------------------------------------------------------- */
/** PCI Error Recovery System (PCI-ERS).  If a PCI device driver provides
 *  a set of callbacks in struct pci_error_handlers, then that device driver
 *  will be notified of PCI bus errors, and will be driven to recovery
 *  when an error occurs.
 */

typedef unsigned int __bitwise pci_ers_result_t;

enum pci_ers_result {
	/* no result/none/not supported in device driver */
	PCI_ERS_RESULT_NONE = (__force pci_ers_result_t) 1,

	/* Device driver can recover without slot reset */
	PCI_ERS_RESULT_CAN_RECOVER = (__force pci_ers_result_t) 2,

	/* Device driver wants slot to be reset. */
	PCI_ERS_RESULT_NEED_RESET = (__force pci_ers_result_t) 3,

	/* Device has completely failed, is unrecoverable */
	PCI_ERS_RESULT_DISCONNECT = (__force pci_ers_result_t) 4,

	/* Device driver is fully recovered and operational */
	PCI_ERS_RESULT_RECOVERED = (__force pci_ers_result_t) 5,

	/* No AER capabilities registered for the driver */
	PCI_ERS_RESULT_NO_AER_DRIVER = (__force pci_ers_result_t) 6,
};

/* PCI bus error event callbacks */
struct pci_error_handlers {
	/* PCI bus error detected on this device */
	pci_ers_result_t (*error_detected)(struct pci_dev *dev,
					   enum pci_channel_state error);

	/* MMIO has been re-enabled, but not DMA */
	pci_ers_result_t (*mmio_enabled)(struct pci_dev *dev);

	/* PCI Express link has been reset */
	pci_ers_result_t (*link_reset)(struct pci_dev *dev);

	/* PCI slot has been reset */
	pci_ers_result_t (*slot_reset)(struct pci_dev *dev);

	/* Device driver may resume normal operations */
	void (*resume)(struct pci_dev *dev);
};

/* ---------------------------------------------------------------- */

struct pci_driver {
	struct list_head node;
	const char *name;
	const struct pci_device_id *id_table;	/* must be non-NULL for probe to be called */
	int  (*probe)  (struct pci_dev *dev, const struct pci_device_id *id);	/* New device inserted */
	void (*remove) (struct pci_dev *dev);	/* Device removed (NULL if not a hot-plug capable driver) */
	int  (*resume_early) (struct pci_dev *dev);
	int  (*resume) (struct pci_dev *dev);	                /* Device woken up */
	void (*shutdown) (struct pci_dev *dev);
	int (*sriov_configure) (struct pci_dev *dev, int num_vfs); /* PF pdev */
	const struct pci_error_handlers *err_handler;
	struct device_driver	driver;
	struct pci_dynids dynids;
};

/**
 * DEFINE_PCI_DEVICE_TABLE - macro used to describe a pci device table
 * @_table: device table name
 *
 * This macro is used to create a struct pci_device_id array (a device table)
 * in a generic manner.
 */
#define DEFINE_PCI_DEVICE_TABLE(_table) \
	const struct pci_device_id _table[]

/**
 * PCI_DEVICE - macro used to describe a specific pci device
 * @vend: the 16 bit PCI Vendor ID
 * @dev: the 16 bit PCI Device ID
 *
 * This macro is used to create a struct pci_device_id that matches a
 * specific device.  The subvendor and subdevice fields will be set to
 * PCI_ANY_ID.
 */
#define PCI_DEVICE(vend,dev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID

/**
 * PCI_DEVICE_SUB - macro used to describe a specific pci device with subsystem
 * @vend: the 16 bit PCI Vendor ID
 * @dev: the 16 bit PCI Device ID
 * @subvend: the 16 bit PCI Subvendor ID
 * @subdev: the 16 bit PCI Subdevice ID
 *
 * This macro is used to create a struct pci_device_id that matches a
 * specific device with subsystem information.
 */
#define PCI_DEVICE_SUB(vend, dev, subvend, subdev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = (subvend), .subdevice = (subdev)

/**
 * PCI_DEVICE_CLASS - macro used to describe a specific pci device class
 * @dev_class: the class, subclass, prog-if triple for this device
 * @dev_class_mask: the class mask for this device
 *
 * This macro is used to create a struct pci_device_id that matches a
 * specific PCI class.  The vendor, device, subvendor, and subdevice
 * fields will be set to PCI_ANY_ID.
 */
#define PCI_DEVICE_CLASS(dev_class,dev_class_mask) \
	.class = (dev_class), .class_mask = (dev_class_mask), \
	.vendor = PCI_ANY_ID, .device = PCI_ANY_ID, \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID

/**
 * PCI_VDEVICE - macro used to describe a specific pci device in short form
 * @vendor: the vendor name
 * @device: the 16 bit PCI Device ID
 *
 * This macro is used to create a struct pci_device_id that matches a
 * specific PCI device.  The subvendor, and subdevice fields will be set
 * to PCI_ANY_ID. The macro allows the next field to follow as the device
 * private data.
 */

#define PCI_VDEVICE(vendor, device)		\
	PCI_VENDOR_ID_##vendor, (device),	\
	PCI_ANY_ID, PCI_ANY_ID, 0, 0


extern struct list_head pci_root_buses;	/* list of all known PCI buses */





int  pci_init(void);
void pci_func_enable(struct pci_dev *f);

#ifdef CONFIG_E1000
int pci_func_attach_E1000(struct pci_dev *f);

int pci_transmit_packet(const void * src,size_t n);
int pci_receive_packet(void * dst);
#endif

#ifdef CONFIG_INFINIBAND
int mlx4_init_one(struct pci_dev *f);
#else
static inline int mlx4_init_one(struct pci_dev *f) { return 0; }
#endif

u32 pci_conf_read(struct pci_dev *f, u32 off, int len);
void pci_conf_write(struct pci_dev *f, u32 off, u32 v, int len);

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

#endif /* _LEGO_PCI_H_ */
