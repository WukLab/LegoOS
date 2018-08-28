/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <lego/pci.h>
#include <lego/slab.h>
#include <lego/list.h>
#include <lego/delay.h>
#include <lego/timer.h>
#include <lego/kernel.h>
#include <lego/resource.h>
#include <lego/dma-mapping.h>

#include <asm/io.h>
#include "pci.h"

#define CARDBUS_LATENCY_TIMER	176	/* secondary latency timer */
#define CARDBUS_RESERVE_BUSNR	3

struct resource busn_resource = {
	.name	= "PCI busn",
	.start	= 0,
	.end	= 255,
	.flags	= IORESOURCE_BUS,
};

LIST_HEAD(pci_root_buses);

/*
 * List of all PCI devices
 * Used for driver to attach device, cause we don't have a nice
 * device subsystem.
 */
LIST_HEAD(pci_devices);

unsigned int pci_flags;

static LIST_HEAD(pci_domain_busn_res_list);

struct pci_domain_busn_res {
	struct list_head list;
	struct resource res;
	int domain_nr;
};

static struct resource *get_pci_domain_busn_res(int domain_nr)
{
	struct pci_domain_busn_res *r;

	list_for_each_entry(r, &pci_domain_busn_res_list, list)
		if (r->domain_nr == domain_nr)
			return &r->res;

	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return NULL;

	r->domain_nr = domain_nr;
	r->res.start = 0;
	r->res.end = 0xff;
	r->res.flags = IORESOURCE_BUS | IORESOURCE_PCI_FIXED;

	list_add_tail(&r->list, &pci_domain_busn_res_list);

	return &r->res;
}

static struct pci_bus *pci_alloc_bus(void)
{
	struct pci_bus *b;

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return NULL;

	INIT_LIST_HEAD(&b->node);
	INIT_LIST_HEAD(&b->children);
	INIT_LIST_HEAD(&b->devices);
	INIT_LIST_HEAD(&b->resources);
	b->max_bus_speed = PCI_SPEED_UNKNOWN;
	b->cur_bus_speed = PCI_SPEED_UNKNOWN;
	return b;
}

static void pci_release_host_bridge_dev(struct device *dev)
{
	struct pci_host_bridge *bridge = to_pci_host_bridge(dev);

	if (bridge->release_fn)
		bridge->release_fn(bridge);

	pci_free_resource_list(&bridge->windows);

	kfree(bridge);
}

static struct pci_host_bridge *pci_alloc_host_bridge(struct pci_bus *b)
{
	struct pci_host_bridge *bridge;

	bridge = kzalloc(sizeof(*bridge), GFP_KERNEL);
	if (!bridge)
		return NULL;

	INIT_LIST_HEAD(&bridge->windows);
	bridge->bus = b;
	return bridge;
}

int pci_bus_insert_busn_res(struct pci_bus *b, int bus, int bus_max)
{
	struct resource *res = &b->busn_res;
	struct resource *parent_res, *conflict;

	res->start = bus;
	res->end = bus_max;
	res->flags = IORESOURCE_BUS;

	if (!pci_is_root_bus(b))
		parent_res = &b->parent->busn_res;
	else {
		parent_res = get_pci_domain_busn_res(pci_domain_nr(b));
		res->flags |= IORESOURCE_PCI_FIXED;
	}

	conflict = insert_resource_conflict(parent_res, res);

	if (conflict)
		pr_info(
			   "busn_res: can not insert %pR under %s%pR (conflicts with %s %pR)\n",
			    res, pci_is_root_bus(b) ? "domain " : "",
			    parent_res, conflict->name, conflict);

	return conflict == NULL;
}

int pci_bus_update_busn_res_end(struct pci_bus *b, int bus_max)
{
	struct resource *res = &b->busn_res;
	struct resource old_res = *res;
	resource_size_t size;
	int ret;

	if (res->start > bus_max)
		return -EINVAL;

	size = bus_max - res->start + 1;
	ret = adjust_resource(res, res->start, size);
	pr_info("busn_res: %pR end %s updated to %02x\n",
		&old_res, ret ? "can not be" : "is", bus_max);

	if (!ret && !res->parent)
		pci_bus_insert_busn_res(b, res->start, res->end);

	return ret;
}

struct pci_bus *pci_create_root_bus(struct device *parent, int bus,
		struct pci_ops *ops, void *sysdata, struct list_head *resources)
{
	struct pci_host_bridge *bridge;
	struct pci_bus *b, *b2;
	struct pci_host_bridge_window *window, *n;
	struct resource *res;
	resource_size_t offset;
	char bus_addr[64];
	char *fmt;

	b = pci_alloc_bus();
	if (!b)
		return NULL;

	b->sysdata = sysdata;
	b->ops = ops;
	b->number = b->busn_res.start = bus;

	b2 = pci_find_bus(pci_domain_nr(b), bus);
	if (b2) {
		/* If we already got to this bus through a different bridge, ignore it */
		pr_debug("bus already known\n");
		goto err_out;
	}

	bridge = pci_alloc_host_bridge(b);
	if (!bridge)
		goto err_out;

	bridge->dev.parent = parent;
	bridge->dev.release = pci_release_host_bridge_dev;
	dev_set_name(&bridge->dev, "pci%04x:%02x", pci_domain_nr(b), bus);

	b->bridge = &bridge->dev;
	b->dev.parent = b->bridge;
	dev_set_name(&b->dev, "%04x:%02x", pci_domain_nr(b), bus);

	printk(KERN_INFO "PCI host bridge to bus %s\n", dev_name(&b->dev));

	/* Add initial resources to the bus */
	list_for_each_entry_safe(window, n, resources, list) {
		list_move_tail(&window->list, &bridge->windows);
		res = window->res;
		offset = window->offset;
		if (res->flags & IORESOURCE_BUS)
			pci_bus_insert_busn_res(b, bus, res->end);
		else
			pci_bus_add_resource(b, res, 0);
		if (offset) {
			if (resource_type(res) == IORESOURCE_IO)
				fmt = " (bus address [%#06llx-%#06llx])";
			else
				fmt = " (bus address [%#010llx-%#010llx])";
			snprintf(bus_addr, sizeof(bus_addr), fmt,
				 (unsigned long long) (res->start - offset),
				 (unsigned long long) (res->end - offset));
		} else
			bus_addr[0] = '\0';
		pr_info("root bus resource %pR%s\n", res, bus_addr);
	}

	down_write(&pci_bus_sem);
	list_add_tail(&b->node, &pci_root_buses);
	up_write(&pci_bus_sem);

	return b;

err_out:
	kfree(b);
	return NULL;
}

struct pci_bus *pci_scan_root_bus(struct device *parent, int bus,
		struct pci_ops *ops, void *sysdata, struct list_head *resources)
{
	struct pci_host_bridge_window *window;
	bool found = false;
	struct pci_bus *b;
	int max;

	list_for_each_entry(window, resources, list)
		if (window->res->flags & IORESOURCE_BUS) {
			found = true;
			break;
		}

	b = pci_create_root_bus(parent, bus, ops, sysdata, resources);
	if (!b)
		return NULL;

	if (!found) {
		pr_info("No busn resource found for root bus, "
			 "will use [bus %02x-ff]\n", bus);
		pci_bus_insert_busn_res(b, bus, 255);
	}

	max = pci_scan_child_bus(b);

	if (!found)
		pci_bus_update_busn_res_end(b, max);

	//pci_bus_add_devices(b);
	return b;
}

static u64 pci_size(u64 base, u64 maxbase, u64 mask)
{
	u64 size = mask & maxbase;	/* Find the significant bits */
	if (!size)
		return 0;

	/* Get the lowest of them to find the decode size, and
	   from that the extent.  */
	size = (size & ~(size-1)) - 1;

	/* base == maxbase can be valid only if the BAR has
	   already been programmed with all 1s.  */
	if (base == maxbase && ((base | size) & mask) != mask)
		return 0;

	return size;
}

static inline unsigned long decode_bar(struct pci_dev *dev, u32 bar)
{
	u32 mem_type;
	unsigned long flags;

	if ((bar & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_IO) {
		flags = bar & ~PCI_BASE_ADDRESS_IO_MASK;
		flags |= IORESOURCE_IO;
		return flags;
	}

	flags = bar & ~PCI_BASE_ADDRESS_MEM_MASK;
	flags |= IORESOURCE_MEM;
	if (flags & PCI_BASE_ADDRESS_MEM_PREFETCH)
		flags |= IORESOURCE_PREFETCH;

	mem_type = bar & PCI_BASE_ADDRESS_MEM_TYPE_MASK;
	switch (mem_type) {
	case PCI_BASE_ADDRESS_MEM_TYPE_32:
		break;
	case PCI_BASE_ADDRESS_MEM_TYPE_1M:
		/* 1M mem BAR treated as 32-bit BAR */
		break;
	case PCI_BASE_ADDRESS_MEM_TYPE_64:
		flags |= IORESOURCE_MEM_64;
		break;
	default:
		/* mem unknown type treated as 32-bit BAR */
		break;
	}
	return flags;
}

/**
 * pci_read_base - read a PCI BAR
 * @dev: the PCI device
 * @type: type of the BAR
 * @res: resource buffer to be filled in
 * @pos: BAR position in the config space
 *
 * Returns 1 if the BAR is 64-bit, or 0 if 32-bit.
 */
int __pci_read_base(struct pci_dev *dev, enum pci_bar_type type,
			struct resource *res, unsigned int pos)
{
	u32 l, sz, mask;
	u16 orig_cmd;
	struct pci_bus_region region, inverted_region;
	bool bar_too_big = false, bar_disabled = false;

	mask = type ? PCI_ROM_ADDRESS_MASK : ~0;

	/* No printks while decoding is disabled! */
	if (!dev->mmio_always_on) {
		pci_read_config_word(dev, PCI_COMMAND, &orig_cmd);
		pci_write_config_word(dev, PCI_COMMAND,
			orig_cmd & ~(PCI_COMMAND_MEMORY | PCI_COMMAND_IO));
	}

	res->name = pci_name(dev);

	pci_read_config_dword(dev, pos, &l);
	pci_write_config_dword(dev, pos, l | mask);
	pci_read_config_dword(dev, pos, &sz);
	pci_write_config_dword(dev, pos, l);

	/*
	 * All bits set in sz means the device isn't working properly.
	 * If the BAR isn't implemented, all bits must be 0.  If it's a
	 * memory BAR or a ROM, bit 0 must be clear; if it's an io BAR, bit
	 * 1 must be clear.
	 */
	if (!sz || sz == 0xffffffff)
		goto fail;

	/*
	 * I don't know how l can have all bits set.  Copied from old code.
	 * Maybe it fixes a bug on some ancient platform.
	 */
	if (l == 0xffffffff)
		l = 0;

	if (type == pci_bar_unknown) {
		res->flags = decode_bar(dev, l);
		res->flags |= IORESOURCE_SIZEALIGN;
		if (res->flags & IORESOURCE_IO) {
			l &= PCI_BASE_ADDRESS_IO_MASK;
			mask = PCI_BASE_ADDRESS_IO_MASK & (u32) IO_SPACE_LIMIT;
		} else {
			l &= PCI_BASE_ADDRESS_MEM_MASK;
			mask = (u32)PCI_BASE_ADDRESS_MEM_MASK;
		}
	} else {
		res->flags |= (l & IORESOURCE_ROM_ENABLE);
		l &= PCI_ROM_ADDRESS_MASK;
		mask = (u32)PCI_ROM_ADDRESS_MASK;
	}

	if (res->flags & IORESOURCE_MEM_64) {
		u64 l64 = l;
		u64 sz64 = sz;
		u64 mask64 = mask | (u64)~0 << 32;

		pci_read_config_dword(dev, pos + 4, &l);
		pci_write_config_dword(dev, pos + 4, ~0);
		pci_read_config_dword(dev, pos + 4, &sz);
		pci_write_config_dword(dev, pos + 4, l);

		l64 |= ((u64)l << 32);
		sz64 |= ((u64)sz << 32);

		sz64 = pci_size(l64, sz64, mask64);

		if (!sz64)
			goto fail;

		if ((sizeof(resource_size_t) < 8) && (sz64 > 0x100000000ULL)) {
			bar_too_big = true;
			goto fail;
		}

		if ((sizeof(resource_size_t) < 8) && l) {
			/* Address above 32-bit boundary; disable the BAR */
			pci_write_config_dword(dev, pos, 0);
			pci_write_config_dword(dev, pos + 4, 0);
			region.start = 0;
			region.end = sz64;
			bar_disabled = true;
		} else {
			region.start = l64;
			region.end = l64 + sz64;
		}
	} else {
		sz = pci_size(l, sz, mask);

		if (!sz)
			goto fail;

		region.start = l;
		region.end = l + sz;
	}

	pcibios_bus_to_resource(dev, res, &region);
	pcibios_resource_to_bus(dev, &inverted_region, res);

	/*
	 * If "A" is a BAR value (a bus address), "bus_to_resource(A)" is
	 * the corresponding resource address (the physical address used by
	 * the CPU.  Converting that resource address back to a bus address
	 * should yield the original BAR value:
	 *
	 *     resource_to_bus(bus_to_resource(A)) == A
	 *
	 * If it doesn't, CPU accesses to "bus_to_resource(A)" will not
	 * be claimed by the device.
	 */
	if (inverted_region.start != region.start) {
		dev_info(&dev->dev, "reg 0x%x: initial BAR value %pa invalid; forcing reassignment\n",
			 pos, &region.start);
		res->flags |= IORESOURCE_UNSET;
		res->end -= res->start;
		res->start = 0;
	}

	goto out;


fail:
	res->flags = 0;
out:
	if (!dev->mmio_always_on)
		pci_write_config_word(dev, PCI_COMMAND, orig_cmd);

	if (bar_too_big)
		dev_err(&dev->dev, "reg 0x%x: can't handle 64-bit BAR\n", pos);
	if (res->flags && !bar_disabled)
		pr_info("    pci %s: reg 0x%x: %pR\n", dev_name(&dev->dev), pos, res);

	return (res->flags & IORESOURCE_MEM_64) ? 1 : 0;
}

static void pci_read_bases(struct pci_dev *dev, unsigned int howmany, int rom)
{
	unsigned int pos, reg;

	for (pos = 0; pos < howmany; pos++) {
		struct resource *res = &dev->resource[pos];
		reg = PCI_BASE_ADDRESS_0 + (pos << 2);
		pos += __pci_read_base(dev, pci_bar_unknown, res, reg);
	}

	if (rom) {
		struct resource *res = &dev->resource[PCI_ROM_RESOURCE];
		dev->rom_base_reg = rom;
		res->flags = IORESOURCE_MEM | IORESOURCE_PREFETCH |
				IORESOURCE_READONLY | IORESOURCE_CACHEABLE |
				IORESOURCE_SIZEALIGN;
		__pci_read_base(dev, pci_bar_mem32, res, rom);
	}
}

static int __pci_bus_find_cap_start(struct pci_bus *bus,
				    unsigned int devfn, u8 hdr_type)
{
	u16 status;

	pci_bus_read_config_word(bus, devfn, PCI_STATUS, &status);
	if (!(status & PCI_STATUS_CAP_LIST))
		return 0;

	switch (hdr_type) {
	case PCI_HEADER_TYPE_NORMAL:
	case PCI_HEADER_TYPE_BRIDGE:
		return PCI_CAPABILITY_LIST;
	case PCI_HEADER_TYPE_CARDBUS:
		return PCI_CB_CAPABILITY_LIST;
	default:
		return 0;
	}

	return 0;
}

#define PCI_FIND_CAP_TTL	48

static int __pci_find_next_cap_ttl(struct pci_bus *bus, unsigned int devfn,
				   u8 pos, int cap, int *ttl)
{
	u8 id;

	while ((*ttl)--) {
		pci_bus_read_config_byte(bus, devfn, pos, &pos);
		if (pos < 0x40)
			break;
		pos &= ~3;
		pci_bus_read_config_byte(bus, devfn, pos + PCI_CAP_LIST_ID,
					 &id);
		if (id == 0xff)
			break;
		if (id == cap)
			return pos;
		pos += PCI_CAP_LIST_NEXT;
	}
	return 0;
}

static int __pci_find_next_cap(struct pci_bus *bus, unsigned int devfn,
			       u8 pos, int cap)
{
	int ttl = PCI_FIND_CAP_TTL;

	return __pci_find_next_cap_ttl(bus, devfn, pos, cap, &ttl);
}

int pci_find_next_capability(struct pci_dev *dev, u8 pos, int cap)
{
	return __pci_find_next_cap(dev->bus, dev->devfn,
				   pos + PCI_CAP_LIST_NEXT, cap);
}

/**
 * pci_find_capability - query for devices' capabilities
 * @dev: PCI device to query
 * @cap: capability code
 *
 * Tell if a device supports a given PCI capability.
 * Returns the address of the requested capability structure within the
 * device's PCI configuration space or 0 in case the device does not
 * support it.  Possible values for @cap:
 *
 *  %PCI_CAP_ID_PM           Power Management
 *  %PCI_CAP_ID_AGP          Accelerated Graphics Port
 *  %PCI_CAP_ID_VPD          Vital Product Data
 *  %PCI_CAP_ID_SLOTID       Slot Identification
 *  %PCI_CAP_ID_MSI          Message Signalled Interrupts
 *  %PCI_CAP_ID_CHSWP        CompactPCI HotSwap
 *  %PCI_CAP_ID_PCIX         PCI-X
 *  %PCI_CAP_ID_EXP          PCI Express
 */
int pci_find_capability(struct pci_dev *dev, int cap)
{
	int pos;

	pos = __pci_bus_find_cap_start(dev->bus, dev->devfn, dev->hdr_type);
	if (pos)
		pos = __pci_find_next_cap(dev->bus, dev->devfn, pos, cap);

	return pos;
}

/**
 * pci_find_next_ext_capability - Find an extended capability
 * @dev: PCI device to query
 * @start: address at which to start looking (0 to start at beginning of list)
 * @cap: capability code
 *
 * Returns the address of the next matching extended capability structure
 * within the device's PCI configuration space or 0 if the device does
 * not support it.  Some capabilities can occur several times, e.g., the
 * vendor-specific capability, and this provides a way to find them all.
 */
int pci_find_next_ext_capability(struct pci_dev *dev, int start, int cap)
{
	u32 header;
	int ttl;
	int pos = PCI_CFG_SPACE_SIZE;

	/* minimum 8 bytes per capability */
	ttl = (PCI_CFG_SPACE_EXP_SIZE - PCI_CFG_SPACE_SIZE) / 8;

	if (dev->cfg_size <= PCI_CFG_SPACE_SIZE)
		return 0;

	if (start)
		pos = start;

	if (pci_read_config_dword(dev, pos, &header) != PCIBIOS_SUCCESSFUL)
		return 0;

	/*
	 * If we have no capabilities, this is indicated by cap ID,
	 * cap version and next pointer all being 0.
	 */
	if (header == 0)
		return 0;

	while (ttl-- > 0) {
		if (PCI_EXT_CAP_ID(header) == cap && pos != start)
			return pos;

		pos = PCI_EXT_CAP_NEXT(header);
		if (pos < PCI_CFG_SPACE_SIZE)
			break;

		if (pci_read_config_dword(dev, pos, &header) != PCIBIOS_SUCCESSFUL)
			break;
	}

	return 0;
}

/**
 * pci_find_ext_capability - Find an extended capability
 * @dev: PCI device to query
 * @cap: capability code
 *
 * Returns the address of the requested extended capability structure
 * within the device's PCI configuration space or 0 if the device does
 * not support it.  Possible values for @cap:
 *
 *  %PCI_EXT_CAP_ID_ERR		Advanced Error Reporting
 *  %PCI_EXT_CAP_ID_VC		Virtual Channel
 *  %PCI_EXT_CAP_ID_DSN		Device Serial Number
 *  %PCI_EXT_CAP_ID_PWR		Power Budgeting
 */
int pci_find_ext_capability(struct pci_dev *dev, int cap)
{
	return pci_find_next_ext_capability(dev, 0, cap);
}

void set_pcie_port_type(struct pci_dev *pdev)
{
	int pos;
	u16 reg16;

	pos = pci_find_capability(pdev, PCI_CAP_ID_EXP);
	if (!pos)
		return;
	pdev->is_pcie = 1;
	pdev->pcie_cap = pos;
	pci_read_config_word(pdev, pos + PCI_EXP_FLAGS, &reg16);
	pdev->pcie_flags_reg = reg16;
	pci_read_config_word(pdev, pos + PCI_EXP_DEVCAP, &reg16);
	pdev->pcie_mpss = reg16 & PCI_EXP_DEVCAP_PAYLOAD;
}

/**
 * pci_cfg_space_size - get the configuration space size of the PCI device.
 * @dev: PCI device
 *
 * Regular PCI devices have 256 bytes, but PCI-X 2 and PCI Express devices
 * have 4096 bytes.  Even if the device is capable, that doesn't mean we can
 * access it.  Maybe we don't have a way to generate extended config space
 * accesses, or the device is behind a reverse Express bridge.  So we try
 * reading the dword at 0x100 which must either be 0 or a valid extended
 * capability header.
 */
int pci_cfg_space_size_ext(struct pci_dev *dev)
{
	u32 status;
	int pos = PCI_CFG_SPACE_SIZE;

	if (pci_read_config_dword(dev, pos, &status) != PCIBIOS_SUCCESSFUL)
		goto fail;
	if (status == 0xffffffff)
		goto fail;

	return PCI_CFG_SPACE_EXP_SIZE;

 fail:
	return PCI_CFG_SPACE_SIZE;
}

int pci_cfg_space_size(struct pci_dev *dev)
{
	int pos;
	u32 status;
	u16 class;

	class = dev->class >> 8;
	if (class == PCI_CLASS_BRIDGE_HOST)
		return pci_cfg_space_size_ext(dev);

	if (!pci_is_pcie(dev)) {
		pos = pci_find_capability(dev, PCI_CAP_ID_PCIX);
		if (!pos)
			goto fail;

		pci_read_config_dword(dev, pos + PCI_X_STATUS, &status);
		if (!(status & (PCI_X_STATUS_266MHZ | PCI_X_STATUS_533MHZ)))
			goto fail;
	}

	return pci_cfg_space_size_ext(dev);

 fail:
	return PCI_CFG_SPACE_SIZE;
}

/*
 * Read interrupt line and base address registers.
 * The architecture-dependent code can tweak these, of course.
 */
static void pci_read_irq(struct pci_dev *dev)
{
	unsigned char irq;

	pci_read_config_byte(dev, PCI_INTERRUPT_PIN, &irq);
	dev->pin = irq;
	if (irq)
		pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &irq);
	dev->irq = irq;
}

void set_pcie_hotplug_bridge(struct pci_dev *pdev)
{
	u32 reg32;

	pcie_capability_read_dword(pdev, PCI_EXP_SLTCAP, &reg32);
	if (reg32 & PCI_EXP_SLTCAP_HPC)
		pdev->is_hotplug_bridge = 1;
}

static void pci_fixup_device(int _x, struct pci_dev *dev)
{
	pr_info_once("%s(): TODO\n", __func__);
}

int pci_set_dma_max_seg_size(struct pci_dev *dev, unsigned int size)
{
	return dma_set_max_seg_size(&dev->dev, size);
}

int pci_set_dma_seg_boundary(struct pci_dev *dev, unsigned long mask)
{
	return dma_set_seg_boundary(&dev->dev, mask);
}

#define LEGACY_IO_RESOURCE	(IORESOURCE_IO | IORESOURCE_PCI_FIXED)

/**
 * pci_setup_device - fill in class and map information of a device
 * @dev: the device structure to fill
 *
 * Initialize the device structure with information about the device's
 * vendor,class,memory and IO-space addresses,IRQ lines etc.
 * Called at initialisation of the PCI subsystem and by CardBus services.
 * Returns 0 on success and negative if unknown type of device (not normal,
 * bridge or CardBus).
 */
int pci_setup_device(struct pci_dev *dev)
{
	u32 class;
	u8 hdr_type;
	int pos = 0;
	struct pci_bus_region region;
	struct resource *res;

	if (pci_read_config_byte(dev, PCI_HEADER_TYPE, &hdr_type))
		return -EIO;

	dev->sysdata = dev->bus->sysdata;
	dev->dev.parent = dev->bus->bridge;
	dev->dev.bus = &pci_bus_type;
	dev->hdr_type = hdr_type & 0x7f;
	dev->multifunction = !!(hdr_type & 0x80);
	dev->error_state = pci_channel_io_normal;
	set_pcie_port_type(dev);

	/* Assume 32-bit PCI; let 64-bit PCI cards (which are far rarer)
	   set this higher, assuming the system even supports it.  */
	dev->_dma_mask = 0xffffffff;

	dev_set_name(&dev->dev, "%04x:%02x:%02x.%d", pci_domain_nr(dev->bus),
		     dev->bus->number, PCI_SLOT(dev->devfn),
		     PCI_FUNC(dev->devfn));

	pci_read_config_dword(dev, PCI_CLASS_REVISION, &class);
	dev->revision = class & 0xff;
	dev->class = class >> 8;		    /* upper 3 bytes */

	pr_info("pci %s: [%04x:%04x] type %02x class %#08x\n",
		dev_name(&dev->dev), dev->vendor, dev->device,
		dev->hdr_type, dev->class);

	/* need to have dev->class ready */
	dev->cfg_size = pci_cfg_space_size(dev);

	/* "Unknown power state" */
	dev->current_state = PCI_UNKNOWN;

	/* Early fixups, before probing the BARs */
	pci_fixup_device(0, dev);

	/* device class may be changed after fixup */
	class = dev->class >> 8;

	switch (dev->hdr_type) {		    /* header type */
	case PCI_HEADER_TYPE_NORMAL:		    /* standard header */
		if (class == PCI_CLASS_BRIDGE_PCI)
			goto bad;
		pci_read_irq(dev);
		pci_read_bases(dev, 6, PCI_ROM_ADDRESS);
		pci_read_config_word(dev, PCI_SUBSYSTEM_VENDOR_ID, &dev->subsystem_vendor);
		pci_read_config_word(dev, PCI_SUBSYSTEM_ID, &dev->subsystem_device);

		/*
		 *	Do the ugly legacy mode stuff here rather than broken chip
		 *	quirk code. Legacy mode ATA controllers have fixed
		 *	addresses. These are not always echoed in BAR0-3, and
		 *	BAR0-3 in a few cases contain junk!
		 */
		if (class == PCI_CLASS_STORAGE_IDE) {
			u8 progif;
			pci_read_config_byte(dev, PCI_CLASS_PROG, &progif);
			if ((progif & 1) == 0) {
				region.start = 0x1F0;
				region.end = 0x1F7;
				res = &dev->resource[0];
				res->flags = LEGACY_IO_RESOURCE;
				pcibios_bus_to_resource(dev, res, &region);
				region.start = 0x3F6;
				region.end = 0x3F6;
				res = &dev->resource[1];
				res->flags = LEGACY_IO_RESOURCE;
				pcibios_bus_to_resource(dev, res, &region);
			}
			if ((progif & 4) == 0) {
				region.start = 0x170;
				region.end = 0x177;
				res = &dev->resource[2];
				res->flags = LEGACY_IO_RESOURCE;
				pcibios_bus_to_resource(dev, res, &region);
				region.start = 0x376;
				region.end = 0x376;
				res = &dev->resource[3];
				res->flags = LEGACY_IO_RESOURCE;
				pcibios_bus_to_resource(dev, res, &region);
			}
		}
		break;

	case PCI_HEADER_TYPE_BRIDGE:		    /* bridge header */
		if (class != PCI_CLASS_BRIDGE_PCI)
			goto bad;
		/* The PCI-to-PCI bridge spec requires that subtractive
		   decoding (i.e. transparent) bridge must have programming
		   interface code of 0x01. */
		pci_read_irq(dev);
		dev->transparent = ((dev->class & 0xff) == 1);
		pci_read_bases(dev, 2, PCI_ROM_ADDRESS1);
		set_pcie_hotplug_bridge(dev);
		pos = pci_find_capability(dev, PCI_CAP_ID_SSVID);
		if (pos) {
			pci_read_config_word(dev, pos + PCI_SSVID_VENDOR_ID, &dev->subsystem_vendor);
			pci_read_config_word(dev, pos + PCI_SSVID_DEVICE_ID, &dev->subsystem_device);
		}
		break;

	case PCI_HEADER_TYPE_CARDBUS:		    /* CardBus bridge header */
		if (class != PCI_CLASS_BRIDGE_CARDBUS)
			goto bad;
		pci_read_irq(dev);
		pci_read_bases(dev, 1, 0);
		pci_read_config_word(dev, PCI_CB_SUBSYSTEM_VENDOR_ID, &dev->subsystem_vendor);
		pci_read_config_word(dev, PCI_CB_SUBSYSTEM_ID, &dev->subsystem_device);
		break;

	default:				    /* unknown header */
		pr_err("unknown header type %02x, "
			"ignoring device\n", dev->hdr_type);
		return -EIO;

	bad:
		pr_err("ignoring class %#08x (doesn't match header "
			"type %02x)\n", dev->class, dev->hdr_type);
		dev->class = PCI_CLASS_NOT_DEFINED;
	}

	/* We found a fine healthy device, go go go... */
	return 0;
}

struct pci_dev *pci_alloc_dev(struct pci_bus *bus)
{
	struct pci_dev *dev;

	dev = kzalloc(sizeof(struct pci_dev), GFP_KERNEL);
	if (!dev)
		return NULL;

	INIT_LIST_HEAD(&dev->bus_list);
	INIT_LIST_HEAD(&dev->device_list);
	dev->bus = bus;

	return dev;
}

bool pci_bus_read_dev_vendor_id(struct pci_bus *bus, int devfn, u32 *l,
				 int crs_timeout)
{
	int delay = 1;

	if (pci_bus_read_config_dword(bus, devfn, PCI_VENDOR_ID, l))
		return false;

	/* some broken boards return 0 or ~0 if a slot is empty: */
	if (*l == 0xffffffff || *l == 0x00000000 ||
	    *l == 0x0000ffff || *l == 0xffff0000)
		return false;

	/* Configuration request Retry Status */
	while (*l == 0xffff0001) {
		if (!crs_timeout)
			return false;

		msleep(delay);
		delay *= 2;
		if (pci_bus_read_config_dword(bus, devfn, PCI_VENDOR_ID, l))
			return false;
		/* Card hasn't responded in 60 seconds?  Must be stuck. */
		if (delay > crs_timeout) {
			printk(KERN_WARNING "pci %04x:%02x:%02x.%d: not "
					"responding\n", pci_domain_nr(bus),
					bus->number, PCI_SLOT(devfn),
					PCI_FUNC(devfn));
			return false;
		}
	}

	return true;
}

/*
 * Read the config data for a PCI device, sanity-check it
 * and fill in the dev structure...
 */
static struct pci_dev *pci_scan_device(struct pci_bus *bus, int devfn)
{
	struct pci_dev *dev;
	u32 l;

	if (!pci_bus_read_dev_vendor_id(bus, devfn, &l, 60*1000))
		return NULL;

	dev = pci_alloc_dev(bus);
	if (!dev)
		return NULL;

	dev->devfn = devfn;
	dev->vendor = l & 0xffff;
	dev->device = (l >> 16) & 0xffff;

	if (pci_setup_device(dev)) {
		kfree(dev);
		return NULL;
	}
	return dev;
}

/*
 * XXX: Looks quite important!!!
 * And this is a good reference to do stuff.
 */
static void pci_init_capabilities(struct pci_dev *dev)
{
	pr_info_once("%s(): TODO\n", __func__);

	/* MSI/MSI-X list */
	pci_msi_init_pci_dev(dev);

	/* Power Management */
	pci_pm_init(dev);

#if 0

	/* Buffers for saving PCIe and PCI-X capabilities */
	pci_allocate_cap_save_buffers(dev);

	/* Vital Product Data */
	pci_vpd_pci22_init(dev);

	/* Alternative Routing-ID Forwarding */
	pci_configure_ari(dev);

	/* Single Root I/O Virtualization */
	pci_iov_init(dev);

	/* Enable ACS P2P upstream forwarding */
	pci_enable_acs(dev);
#endif
}

/*
 * Add @dev to its @bus. This make @dev visible to other friends.
 * It is always a good practice to write the de-init along with
 * init function. But now Lego does not have any support for removing
 * PCI devices.
 */
void pci_device_add(struct pci_dev *dev, struct pci_bus *bus)
{
	device_initialize(&dev->dev);
	/*
	 * TODO: setup the REAL numa node that
	 * the device is attached to.
	 */

	dev->dev.dma_mask = &dev->_dma_mask;
	dev->dev.dma_parms = &dev->dma_parms;
	dev->dev.coherent_dma_mask = 0xffffffffull;

	pci_set_dma_max_seg_size(dev, 65536);
	pci_set_dma_seg_boundary(dev, 0xffffffff);

	/* Fix up broken headers */
	pci_fixup_device(pci_fixup_header, dev);

	/* Clear the state_saved flag. */
	dev->state_saved = false;

	/* Initialize various capabilities */
	pci_init_capabilities(dev);

	/*
	 * Add the device to our list of discovered devices
	 * and the bus list for fixup functions, etc.
	 */
	down_write(&pci_bus_sem);
	list_add_tail(&dev->bus_list, &bus->devices);
	list_add_tail(&dev->device_list, &pci_devices);
	up_write(&pci_bus_sem);
}

/*
 * HACK!!!
 *
 * This is the ultimate function you might want to look into. It has everything
 * about setting up a PCI device: alloc data structure, fill with info read from
 * device conf space, and linked into other data structures.
 *
 * It also has great details on how different PCI/PCIe functionalities are dealt with.
 */
struct pci_dev *pci_scan_single_device(struct pci_bus *bus, int devfn)
{
	struct pci_dev *dev;

	/* Check if it is already added */
	dev = pci_get_slot(bus, devfn);
	if (dev)
		return dev;

	dev = pci_scan_device(bus, devfn);
	if (!dev)
		return NULL;

	pci_device_add(dev, bus);
	return dev;
}

static unsigned next_fn(struct pci_bus *bus, struct pci_dev *dev, unsigned fn)
{
	int pos;
	u16 cap = 0;
	unsigned next_fn;

	if (pci_ari_enabled(bus)) {
		if (!dev)
			return 0;
		pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_ARI);
		if (!pos)
			return 0;

		pci_read_config_word(dev, pos + PCI_ARI_CAP, &cap);
		next_fn = PCI_ARI_CAP_NFN(cap);
		if (next_fn <= fn)
			return 0;	/* protect against malformed list */

		return next_fn;
	}

	/* dev may be NULL for non-contiguous multifunction devices */
	if (!dev || dev->multifunction)
		return (fn + 1) % 8;

	return 0;
}

static int only_one_child(struct pci_bus *bus)
{
	struct pci_dev *parent = bus->self;

	if (!parent || !pci_is_pcie(parent))
		return 0;
	if (pci_pcie_type(parent) == PCI_EXP_TYPE_ROOT_PORT)
		return 1;
	if (pci_pcie_type(parent) == PCI_EXP_TYPE_DOWNSTREAM &&
	    !pci_has_flag(PCI_SCAN_ALL_PCIE_DEVS))
		return 1;
	return 0;
}

/*
 * pcie_aspm_init_link_state: Initiate PCI express link state.
 * It is called after the pcie and its children devices are scaned.
 * @pdev: the root port or switch downstream port
 */
void pcie_aspm_init_link_state(struct pci_dev *pdev)
{
	pr_info_once("%s(): TODO\n", __func__);
}

/**
 * pci_scan_slot - scan a PCI slot on a bus for devices.
 * @bus: PCI bus to scan
 * @devfn: slot number to scan (must have zero function.)
 *
 * Scan a PCI slot on the specified PCI bus for devices, adding
 * discovered devices to the @bus->devices list.  New devices
 * will not have is_added set.
 *
 * Returns the number of new devices found.
 */
int pci_scan_slot(struct pci_bus *bus, int devfn)
{
	unsigned fn, nr = 0;
	struct pci_dev *dev;

	/* Already scanned the entire slot */
	if (only_one_child(bus) && (devfn > 0))
		return 0;

	dev = pci_scan_single_device(bus, devfn);
	if (!dev)
		return 0;
	if (!dev->is_added)
		nr++;

	/* multifunction devices? */
	for (fn = next_fn(bus, dev, 0); fn > 0; fn = next_fn(bus, dev, fn)) {
		dev = pci_scan_single_device(bus, devfn + fn);
		if (dev) {
			if (!dev->is_added)
				nr++;
			dev->multifunction = 1;
		}
	}

	/* only one slot has pcie device */
	if (bus->self && nr)
		pcie_aspm_init_link_state(bus->self);

	return nr;
}

static unsigned char pcix_bus_speed[] = {
	PCI_SPEED_UNKNOWN,		/* 0 */
	PCI_SPEED_66MHz_PCIX,		/* 1 */
	PCI_SPEED_100MHz_PCIX,		/* 2 */
	PCI_SPEED_133MHz_PCIX,		/* 3 */
	PCI_SPEED_UNKNOWN,		/* 4 */
	PCI_SPEED_66MHz_PCIX_ECC,	/* 5 */
	PCI_SPEED_100MHz_PCIX_ECC,	/* 6 */
	PCI_SPEED_133MHz_PCIX_ECC,	/* 7 */
	PCI_SPEED_UNKNOWN,		/* 8 */
	PCI_SPEED_66MHz_PCIX_266,	/* 9 */
	PCI_SPEED_100MHz_PCIX_266,	/* A */
	PCI_SPEED_133MHz_PCIX_266,	/* B */
	PCI_SPEED_UNKNOWN,		/* C */
	PCI_SPEED_66MHz_PCIX_533,	/* D */
	PCI_SPEED_100MHz_PCIX_533,	/* E */
	PCI_SPEED_133MHz_PCIX_533	/* F */
};

static unsigned char pcie_link_speed[] = {
	PCI_SPEED_UNKNOWN,		/* 0 */
	PCIE_SPEED_2_5GT,		/* 1 */
	PCIE_SPEED_5_0GT,		/* 2 */
	PCIE_SPEED_8_0GT,		/* 3 */
	PCI_SPEED_UNKNOWN,		/* 4 */
	PCI_SPEED_UNKNOWN,		/* 5 */
	PCI_SPEED_UNKNOWN,		/* 6 */
	PCI_SPEED_UNKNOWN,		/* 7 */
	PCI_SPEED_UNKNOWN,		/* 8 */
	PCI_SPEED_UNKNOWN,		/* 9 */
	PCI_SPEED_UNKNOWN,		/* A */
	PCI_SPEED_UNKNOWN,		/* B */
	PCI_SPEED_UNKNOWN,		/* C */
	PCI_SPEED_UNKNOWN,		/* D */
	PCI_SPEED_UNKNOWN,		/* E */
	PCI_SPEED_UNKNOWN		/* F */
};

void pcie_update_link_speed(struct pci_bus *bus, u16 linksta)
{
	bus->cur_bus_speed = pcie_link_speed[linksta & PCI_EXP_LNKSTA_CLS];
}

static unsigned char agp_speeds[] = {
	AGP_UNKNOWN,
	AGP_1X,
	AGP_2X,
	AGP_4X,
	AGP_8X
};

static enum pci_bus_speed agp_speed(int agp3, int agpstat)
{
	int index = 0;

	if (agpstat & 4)
		index = 3;
	else if (agpstat & 2)
		index = 2;
	else if (agpstat & 1)
		index = 1;
	else
		goto out;

	if (agp3) {
		index += 2;
		if (index == 5)
			index = 0;
	}

 out:
	return agp_speeds[index];
}

static void pci_set_bus_speed(struct pci_bus *bus)
{
	struct pci_dev *bridge = bus->self;
	int pos;

	pos = pci_find_capability(bridge, PCI_CAP_ID_AGP);
	if (!pos)
		pos = pci_find_capability(bridge, PCI_CAP_ID_AGP3);
	if (pos) {
		u32 agpstat, agpcmd;

		pci_read_config_dword(bridge, pos + PCI_AGP_STATUS, &agpstat);
		bus->max_bus_speed = agp_speed(agpstat & 8, agpstat & 7);

		pci_read_config_dword(bridge, pos + PCI_AGP_COMMAND, &agpcmd);
		bus->cur_bus_speed = agp_speed(agpstat & 8, agpcmd & 7);
	}

	pos = pci_find_capability(bridge, PCI_CAP_ID_PCIX);
	if (pos) {
		u16 status;
		enum pci_bus_speed max;

		pci_read_config_word(bridge, pos + PCI_X_BRIDGE_SSTATUS,
				     &status);

		if (status & PCI_X_SSTATUS_533MHZ) {
			max = PCI_SPEED_133MHz_PCIX_533;
		} else if (status & PCI_X_SSTATUS_266MHZ) {
			max = PCI_SPEED_133MHz_PCIX_266;
		} else if (status & PCI_X_SSTATUS_133MHZ) {
			if ((status & PCI_X_SSTATUS_VERS) == PCI_X_SSTATUS_V2) {
				max = PCI_SPEED_133MHz_PCIX_ECC;
			} else {
				max = PCI_SPEED_133MHz_PCIX;
			}
		} else {
			max = PCI_SPEED_66MHz_PCIX;
		}

		bus->max_bus_speed = max;
		bus->cur_bus_speed = pcix_bus_speed[
			(status & PCI_X_SSTATUS_FREQ) >> 6];

		return;
	}

	pos = pci_find_capability(bridge, PCI_CAP_ID_EXP);
	if (pos) {
		u32 linkcap;
		u16 linksta;

		pcie_capability_read_dword(bridge, PCI_EXP_LNKCAP, &linkcap);
		bus->max_bus_speed = pcie_link_speed[linkcap & PCI_EXP_LNKCAP_SLS];

		pcie_capability_read_word(bridge, PCI_EXP_LNKSTA, &linksta);
		pcie_update_link_speed(bus, linksta);
	}
}

static struct pci_bus *pci_alloc_child_bus(struct pci_bus *parent,
					   struct pci_dev *bridge, int busnr)
{
	struct pci_bus *child;
	int i;

	/*
	 * Allocate a new bus, and inherit stuff from the parent..
	 */
	child = pci_alloc_bus();
	if (!child)
		return NULL;

	child->parent = parent;
	child->ops = parent->ops;
	child->sysdata = parent->sysdata;
	child->bus_flags = parent->bus_flags;

	/* initialize some portions of the bus device, but don't register it
	 * now as the parent is not properly set up yet.
	 */
	dev_set_name(&child->dev, "%04x:%02x", pci_domain_nr(child), busnr);

	/*
	 * Set up the primary, secondary and subordinate
	 * bus numbers.
	 */
	child->number = child->busn_res.start = busnr;
	child->primary = parent->busn_res.start;
	child->busn_res.end = 0xff;

	if (!bridge) {
		child->dev.parent = parent->bridge;
		goto add_dev;
	}

	child->self = bridge;
	child->bridge = &bridge->dev;
	child->dev.parent = child->bridge;
	pci_set_bus_speed(child);

	/* Set up default resource pointers and names.. */
	for (i = 0; i < PCI_BRIDGE_RESOURCE_NUM; i++) {
		child->resource[i] = &bridge->resource[PCI_BRIDGE_RESOURCES+i];
		child->resource[i]->name = child->name;
	}
	bridge->subordinate = child;

add_dev:
	/*
	 * HACK!!!
	 * Lego omit some add callback here,
	 * which is fine I think.
	 */
	return child;
}

struct pci_bus *pci_add_new_bus(struct pci_bus *parent, struct pci_dev *dev, int busnr)
{
	struct pci_bus *child;

	child = pci_alloc_child_bus(parent, dev, busnr);
	if (child) {
		down_write(&pci_bus_sem);
		list_add_tail(&child->node, &parent->children);
		up_write(&pci_bus_sem);
	}
	return child;
}

static void pci_fixup_parent_subordinate_busnr(struct pci_bus *child, int max)
{
	struct pci_bus *parent = child->parent;

	/* Attempts to fix that up are really dangerous unless
	   we're going to re-assign all bus numbers. */
	if (!pcibios_assign_all_busses())
		return;

	while (parent->parent && parent->busn_res.end < max) {
		parent->busn_res.end = max;
		pci_write_config_byte(parent->self, PCI_SUBORDINATE_BUS, max);
		parent = parent->parent;
	}
}

/*
 * If it's a bridge, configure it and scan the bus behind it.
 * For CardBus bridges, we don't scan behind as the devices will
 * be handled by the bridge driver itself.
 *
 * We need to process bridges in two passes -- first we scan those
 * already configured by the BIOS and after we are done with all of
 * them, we proceed to assigning numbers to the remaining buses in
 * order to avoid overlaps between old and new bus numbers.
 */
int pci_scan_bridge(struct pci_bus *bus, struct pci_dev *dev, int max, int pass)
{
	struct pci_bus *child;
	int is_cardbus = (dev->hdr_type == PCI_HEADER_TYPE_CARDBUS);
	u32 buses, i, j = 0;
	u16 bctl;
	u8 primary, secondary, subordinate;
	int broken = 0;

	pci_read_config_dword(dev, PCI_PRIMARY_BUS, &buses);
	primary = buses & 0xFF;
	secondary = (buses >> 8) & 0xFF;
	subordinate = (buses >> 16) & 0xFF;

	pr_info("pci %s: scanning [bus %02x-%02x] behind bridge, pass %d\n",
		dev_name(&dev->dev), secondary, subordinate, pass);

	if (!primary && (primary != bus->number) && secondary && subordinate) {
		pr_warn("pci %s: Primary bus is hard wired to 0\n", dev_name(&dev->dev));
		primary = bus->number;
	}

	/* Check if setup is sensible at all */
	if (!pass &&
	    (primary != bus->number || secondary <= bus->number ||
	     secondary > subordinate)) {
		pr_info("pci %s: bridge configuration invalid ([bus %02x-%02x]), reconfiguring\n",
			 dev_name(&dev->dev), secondary, subordinate);
		broken = 1;
	}

	/* Disable MasterAbortMode during probing to avoid reporting
	   of bus errors (in some architectures) */
	pci_read_config_word(dev, PCI_BRIDGE_CONTROL, &bctl);
	pci_write_config_word(dev, PCI_BRIDGE_CONTROL,
			      bctl & ~PCI_BRIDGE_CTL_MASTER_ABORT);

	if ((secondary || subordinate) && !pcibios_assign_all_busses() &&
	    !is_cardbus && !broken) {
		unsigned int cmax;
		/*
		 * Bus already configured by firmware, process it in the first
		 * pass and just note the configuration.
		 */
		if (pass)
			goto out;

		/*
		 * If we already got to this bus through a different bridge,
		 * don't re-add it. This can happen with the i450NX chipset.
		 *
		 * However, we continue to descend down the hierarchy and
		 * scan remaining child buses.
		 */
		child = pci_find_bus(pci_domain_nr(bus), secondary);
		if (!child) {
			child = pci_add_new_bus(bus, dev, secondary);
			if (!child)
				goto out;
			child->primary = primary;
			pci_bus_insert_busn_res(child, secondary, subordinate);
			child->bridge_ctl = bctl;
		}

		cmax = pci_scan_child_bus(child);
		if (cmax > max)
			max = cmax;
		if (child->busn_res.end > max)
			max = child->busn_res.end;
	} else {
		/*
		 * We need to assign a number to this bus which we always
		 * do in the second pass.
		 */
		if (!pass) {
			if (pcibios_assign_all_busses() || broken)
				/* Temporarily disable forwarding of the
				   configuration cycles on all bridges in
				   this bus segment to avoid possible
				   conflicts in the second pass between two
				   bridges programmed with overlapping
				   bus ranges. */
				pci_write_config_dword(dev, PCI_PRIMARY_BUS,
						       buses & ~0xffffff);
			goto out;
		}

		/* Clear errors */
		pci_write_config_word(dev, PCI_STATUS, 0xffff);

		/* Prevent assigning a bus number that already exists.
		 * This can happen when a bridge is hot-plugged, so in
		 * this case we only re-scan this bus. */
		child = pci_find_bus(pci_domain_nr(bus), max+1);
		if (!child) {
			child = pci_add_new_bus(bus, dev, ++max);
			if (!child)
				goto out;
			pci_bus_insert_busn_res(child, max, 0xff);
		}
		buses = (buses & 0xff000000)
		      | ((unsigned int)(child->primary)     <<  0)
		      | ((unsigned int)(child->busn_res.start)   <<  8)
		      | ((unsigned int)(child->busn_res.end) << 16);

		/*
		 * yenta.c forces a secondary latency timer of 176.
		 * Copy that behaviour here.
		 */
		if (is_cardbus) {
			buses &= ~0xff000000;
			buses |= CARDBUS_LATENCY_TIMER << 24;
		}

		/*
		 * We need to blast all three values with a single write.
		 */
		pci_write_config_dword(dev, PCI_PRIMARY_BUS, buses);

		if (!is_cardbus) {
			child->bridge_ctl = bctl;
			/*
			 * Adjust subordinate busnr in parent buses.
			 * We do this before scanning for children because
			 * some devices may not be detected if the bios
			 * was lazy.
			 */
			pci_fixup_parent_subordinate_busnr(child, max);
			/* Now we can scan all subordinate buses... */
			max = pci_scan_child_bus(child);
			/*
			 * now fix it up again since we have found
			 * the real value of max.
			 */
			pci_fixup_parent_subordinate_busnr(child, max);
		} else {
			/*
			 * For CardBus bridges, we leave 4 bus numbers
			 * as cards with a PCI-to-PCI bridge can be
			 * inserted later.
			 */
			for (i=0; i<CARDBUS_RESERVE_BUSNR; i++) {
				struct pci_bus *parent = bus;
				if (pci_find_bus(pci_domain_nr(bus),
							max+i+1))
					break;
				while (parent->parent) {
					if ((!pcibios_assign_all_busses()) &&
					    (parent->busn_res.end > max) &&
					    (parent->busn_res.end <= max+i)) {
						j = 1;
					}
					parent = parent->parent;
				}
				if (j) {
					/*
					 * Often, there are two cardbus bridges
					 * -- try to leave one valid bus number
					 * for each one.
					 */
					i /= 2;
					break;
				}
			}
			max += i;
			pci_fixup_parent_subordinate_busnr(child, max);
		}
		/*
		 * Set the subordinate bus number to its real value.
		 */
		pci_bus_update_busn_res_end(child, max);
		pci_write_config_byte(dev, PCI_SUBORDINATE_BUS, max);
	}

	sprintf(child->name,
		(is_cardbus ? "PCI CardBus %04x:%02x" : "PCI Bus %04x:%02x"),
		pci_domain_nr(bus), child->number);

	/* Has only triggered on CardBus, fixup is in yenta_socket */
	while (bus->parent) {
		if ((child->busn_res.end > bus->busn_res.end) ||
		    (child->number > bus->busn_res.end) ||
		    (child->number < bus->number) ||
		    (child->busn_res.end < bus->number)) {
			pr_info("pci %s %pR %s "
				"hidden behind%s bridge %s %pR\n",
				dev_name(&child->dev),
				&child->busn_res,
				(bus->number > child->busn_res.end &&
				 bus->busn_res.end < child->number) ?
					"wholly" : "partially",
				bus->self->transparent ? " transparent" : "",
				dev_name(&bus->dev),
				&bus->busn_res);
		}
		bus = bus->parent;
	}

out:
	pci_write_config_word(dev, PCI_BRIDGE_CONTROL, bctl);

	return max;
}

/*
 * Called after each bus is probed, but before its children
 * are examined.
 *
 * XXX: Looks like we don't need this guy. ;-)
 */
void pcibios_fixup_bus(struct pci_bus *b)
{
}

/**
 * pci_iov_bus_range - find bus range used by Virtual Function
 * @bus: the PCI bus
 *
 * Returns max number of buses (exclude current one) used by Virtual
 * Functions.
 *
 * XXX: not sure if we need this. As long as we are not using SR-IOV'ed
 * device, I guess we are safe?
 */
static inline int pci_iov_bus_range(struct pci_bus *bus)
{
	return 0;
}

/*
 * This function will sacn this @bus, slot by slot, function by function.
 * It will add any found devices into the PCI subsystem. If a bridge is found,
 * it will call pci_scan_bridge(), which will recursively scan underlying buses.
 */
unsigned int pci_scan_child_bus(struct pci_bus *bus)
{
	unsigned int devfn, pass, max = bus->busn_res.start;
	struct pci_dev *dev;

	pr_debug("%s() pci %s scanning bus\n",
		__func__, dev_name(&bus->dev));

	/* Go find them, Rover! */
	for (devfn = 0; devfn < 0x100; devfn += 8)
		pci_scan_slot(bus, devfn);

	/* Reserve buses for SR-IOV capability. */
	max += pci_iov_bus_range(bus);

	/*
	 * After performing arch-dependent fixup of the bus, look behind
	 * all PCI-to-PCI bridges on this bus.
	 */
	if (!bus->is_added) {
#if 0
		pr_debug("%s() pci %s fixups for bus\n",
			__func__, dev_name(&bus->dev));
#endif
		pcibios_fixup_bus(bus);
		bus->is_added = 1;
	}

	for (pass=0; pass < 2; pass++)
		list_for_each_entry(dev, &bus->devices, bus_list) {
			if (dev->hdr_type == PCI_HEADER_TYPE_BRIDGE ||
			    dev->hdr_type == PCI_HEADER_TYPE_CARDBUS)
				max = pci_scan_bridge(bus, dev, max, pass);
		}

	/*
	 * We've scanned the bus and so we know all about what's on
	 * the other side of any bridges that may be on this bus plus
	 * any devices.
	 *
	 * Return how far we've got finding sub-buses.
	 */
	return max;
}
