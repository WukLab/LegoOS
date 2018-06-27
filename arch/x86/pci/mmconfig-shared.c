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
#include <lego/acpi.h>
#include <lego/list.h>
#include <lego/mutex.h>
#include <lego/kernel.h>
#include <asm/asm.h>
#include <asm/pci.h>
#include <asm/e820.h>

/*
 * mmconfig-shared.c - Low-level direct PCI config space access via
 *                     MMCONFIG - common code between i386 and x86-64.
 *
 * This code does:
 * - known chipset handling
 * - ACPI decoding and validation
 *
 * Per-architecture code takes care of the mappings and accesses
 * themselves.
 */

#define PREFIX "PCI: "

/* Indicate if the mmcfg resources have been placed into the resource table. */
static bool pci_mmcfg_running_state;
static bool pci_mmcfg_arch_init_failed;
static DEFINE_MUTEX(pci_mmcfg_lock);

LIST_HEAD(pci_mmcfg_list);

static __init void pci_mmconfig_remove(struct pci_mmcfg_region *cfg)
{
	if (cfg->res.parent)
		release_resource(&cfg->res);
	list_del(&cfg->list);
	kfree(cfg);
}

static __init void free_all_mmcfg(void)
{
	struct pci_mmcfg_region *cfg, *tmp;

	pci_mmcfg_arch_free();
	list_for_each_entry_safe(cfg, tmp, &pci_mmcfg_list, list)
		pci_mmconfig_remove(cfg);
}

/*
 * Called with @pci_mmcfg_lock held.
 */
static void list_add_sorted(struct pci_mmcfg_region *new)
{
	struct pci_mmcfg_region *cfg;

	/* keep list sorted by segment and starting bus number */
	list_for_each_entry(cfg, &pci_mmcfg_list, list) {
		if (cfg->segment > new->segment ||
		    (cfg->segment == new->segment &&
		     cfg->start_bus >= new->start_bus)) {
			list_add_tail(&new->list, &cfg->list);
			return;
		}
	}
	list_add_tail(&new->list, &pci_mmcfg_list);
}

static struct pci_mmcfg_region *pci_mmconfig_alloc(int segment, int start,
						   int end, u64 addr)
{
	struct pci_mmcfg_region *new;
	struct resource *res;

	if (addr == 0)
		return NULL;

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return NULL;

	new->address = addr;
	new->segment = segment;
	new->start_bus = start;
	new->end_bus = end;

	res = &new->res;
	res->start = addr + PCI_MMCFG_BUS_OFFSET(start);
	res->end = addr + PCI_MMCFG_BUS_OFFSET(end + 1) - 1;
	res->flags = IORESOURCE_MEM | IORESOURCE_BUSY;
	snprintf(new->name, PCI_MMCFG_RESOURCE_NAME_LEN,
		 "PCI MMCONFIG %04x [bus %02x-%02x]", segment, start, end);
	res->name = new->name;

	return new;
}

static __init struct pci_mmcfg_region *pci_mmconfig_add(int segment, int start,
							int end, u64 addr)
{
	struct pci_mmcfg_region *new;

	new = pci_mmconfig_alloc(segment, start, end, addr);
	if (new) {
		mutex_lock(&pci_mmcfg_lock);
		list_add_sorted(new);
		mutex_unlock(&pci_mmcfg_lock);

		pr_info(PREFIX
		       "MMCONFIG for domain %04x [bus %02x-%02x] at %pR "
		       "(base %#lx)\n",
		       segment, start, end, &new->res, (unsigned long)addr);
	}

	return new;
}

struct pci_mmcfg_region *pci_mmconfig_lookup(int segment, int bus)
{
	struct pci_mmcfg_region *cfg;

	list_for_each_entry(cfg, &pci_mmcfg_list, list)
		if (cfg->segment == segment &&
		    cfg->start_bus <= bus && bus <= cfg->end_bus)
			return cfg;

	return NULL;
}

static const char __init *pci_mmcfg_e7520(void)
{
	u32 win;
	raw_pci_ops->read(0, 0, PCI_DEVFN(0, 0), 0xce, 2, &win);

	win = win & 0xf000;
	if (win == 0x0000 || win == 0xf000)
		return NULL;

	if (pci_mmconfig_add(0, 0, 255, win << 16) == NULL)
		return NULL;

	return "Intel Corporation E7520 Memory Controller Hub";
}

static const char __init *pci_mmcfg_intel_945(void)
{
	u32 pciexbar, mask = 0, len = 0;

	raw_pci_ops->read(0, 0, PCI_DEVFN(0, 0), 0x48, 4, &pciexbar);

	/* Enable bit */
	if (!(pciexbar & 1))
		return NULL;

	/* Size bits */
	switch ((pciexbar >> 1) & 3) {
	case 0:
		mask = 0xf0000000U;
		len  = 0x10000000U;
		break;
	case 1:
		mask = 0xf8000000U;
		len  = 0x08000000U;
		break;
	case 2:
		mask = 0xfc000000U;
		len  = 0x04000000U;
		break;
	default:
		return NULL;
	}

	/* Errata #2, things break when not aligned on a 256Mb boundary */
	/* Can only happen in 64M/128M mode */

	if ((pciexbar & mask) & 0x0fffffffU)
		return NULL;

	/* Don't hit the APIC registers and their friends */
	if ((pciexbar & mask) >= 0xf0000000U)
		return NULL;

	if (pci_mmconfig_add(0, 0, (len >> 20) - 1, pciexbar & mask) == NULL)
		return NULL;

	return "Intel Corporation 945G/GZ/P/PL Express Memory Controller Hub";
}

struct pci_mmcfg_hostbridge_probe {
	u32 bus;
	u32 devfn;
	u32 vendor;
	u32 device;
	const char *(*probe)(void);
};

static struct pci_mmcfg_hostbridge_probe pci_mmcfg_probes[] __initdata = {
	{ 0, PCI_DEVFN(0, 0), PCI_VENDOR_ID_INTEL,
	  PCI_DEVICE_ID_INTEL_E7520_MCH, pci_mmcfg_e7520 },
	{ 0, PCI_DEVFN(0, 0), PCI_VENDOR_ID_INTEL,
	  PCI_DEVICE_ID_INTEL_82945G_HB, pci_mmcfg_intel_945 },
};

static void __init pci_mmcfg_check_end_bus_number(void)
{
	struct pci_mmcfg_region *cfg, *cfgx;

	/* Fixup overlaps */
	list_for_each_entry(cfg, &pci_mmcfg_list, list) {
		if (cfg->end_bus < cfg->start_bus)
			cfg->end_bus = 255;

		/* Don't access the list head ! */
		if (cfg->list.next == &pci_mmcfg_list)
			break;

		cfgx = list_entry(cfg->list.next, typeof(*cfg), list);
		if (cfg->end_bus >= cfgx->start_bus)
			cfg->end_bus = cfgx->start_bus - 1;
	}
}

/*
 * Check pre-defined hostbridges..
 * Mostly, you are not using these bridge (not sure though).
 */
static int __init pci_mmcfg_check_hostbridge(void)
{
	u32 l;
	u32 bus, devfn;
	u16 vendor, device;
	int i;
	const char *name;

	if (!raw_pci_ops)
		return 0;

	free_all_mmcfg();

	for (i = 0; i < ARRAY_SIZE(pci_mmcfg_probes); i++) {
		bus =  pci_mmcfg_probes[i].bus;
		devfn = pci_mmcfg_probes[i].devfn;
		raw_pci_ops->read(0, bus, devfn, 0, 4, &l);
		vendor = l & 0xffff;
		device = (l >> 16) & 0xffff;

		name = NULL;
		if (pci_mmcfg_probes[i].vendor == vendor &&
		    pci_mmcfg_probes[i].device == device)
			name = pci_mmcfg_probes[i].probe();

		if (name)
			pr_info(PREFIX "%s with MMCONFIG support\n", name);
	}

	/* some end_bus_number is crazy, fix it */
	pci_mmcfg_check_end_bus_number();

	return !list_empty(&pci_mmcfg_list);
}

typedef int (*check_reserved_t)(u64 start, u64 end, unsigned type);

static int is_mmconf_reserved(check_reserved_t is_reserved,
				    struct pci_mmcfg_region *cfg,
				    struct device *dev, int with_e820)
{
	u64 addr = cfg->res.start;
	u64 size = resource_size(&cfg->res);
	u64 old_size = size;
	int num_buses;
	char *method = with_e820 ? "E820" : "ACPI motherboard resources";

	while (!is_reserved(addr, addr + size, E820_RESERVED)) {
		size >>= 1;
		if (size < (16UL<<20))
			break;
	}

	if (size < (16UL<<20) && size != old_size)
		return 0;

	pr_info(PREFIX "MMCONFIG at %pR reserved in %s\n",
	       &cfg->res, method);

	if (old_size != size) {
		/* update end_bus */
		cfg->end_bus = cfg->start_bus + ((size>>20) - 1);
		num_buses = cfg->end_bus - cfg->start_bus + 1;
		cfg->res.end = cfg->res.start +
		    PCI_MMCFG_BUS_OFFSET(num_buses) - 1;
		snprintf(cfg->name, PCI_MMCFG_RESOURCE_NAME_LEN,
			 "PCI MMCONFIG %04x [bus %02x-%02x]",
			 cfg->segment, cfg->start_bus, cfg->end_bus);

		pr_info(PREFIX
			"MMCONFIG for %04x [bus%02x-%02x] "
			"at %pR (base %#lx) (size reduced!)\n",
			cfg->segment, cfg->start_bus, cfg->end_bus,
			&cfg->res, (unsigned long) cfg->address);
	}

	return 1;
}

static int pci_mmcfg_check_reserved(struct device *dev,
		  struct pci_mmcfg_region *cfg, int early)
{
	/*
	 * e820_all_mapped() is marked as __init.
	 * All entries from ACPI MCFG table have been checked at boot time.
	 * For MCFG information constructed from hotpluggable host bridge's
	 * _CBA method, just assume it's reserved.
	 */
	if (pci_mmcfg_running_state)
		return 1;

	/* Don't try to do this check unless configuration
	   type 1 is available. how about type 2 ?*/
	if (raw_pci_ops)
		return is_mmconf_reserved(e820_all_mapped, cfg, dev, 1);

	return 0;
}

static void __init pci_mmcfg_reject_broken(int early)
{
	struct pci_mmcfg_region *cfg;

	list_for_each_entry(cfg, &pci_mmcfg_list, list) {
		if (pci_mmcfg_check_reserved(NULL, cfg, early) == 0) {
			pr_info(PREFIX "not using MMCONFIG\n");
			free_all_mmcfg();
			return;
		}
	}
}

static int __init acpi_mcfg_check_entry(struct acpi_table_mcfg *mcfg,
					struct acpi_mcfg_allocation *cfg)
{
	if (cfg->address < 0xFFFFFFFF)
		return 0;

	if (!strncmp(mcfg->header.oem_id, "SGI", 3))
		return 0;

	/*
	 * XXX:
	 * Lego omit the BIOS year check here.
	 * Assume we are running on a new system.
	 */
	if (mcfg->header.revision >= 1)
		return 0;

	pr_err(PREFIX "MCFG region for %04x [bus %02x-%02x] at %#llx "
	       "is above 4GB, ignored\n", cfg->pci_segment,
	       cfg->start_bus_number, cfg->end_bus_number, cfg->address);
	return -EINVAL;
}

static int __init pci_parse_mcfg(struct acpi_table_header *header)
{
	struct acpi_table_mcfg *mcfg;
	struct acpi_mcfg_allocation *cfg_table, *cfg;
	unsigned long i;
	int entries;

	if (!header)
		return -EINVAL;

	mcfg = (struct acpi_table_mcfg *)header;

	/* how many config structures do we have */
	free_all_mmcfg();
	entries = 0;
	i = header->length - sizeof(struct acpi_table_mcfg);
	while (i >= sizeof(struct acpi_mcfg_allocation)) {
		entries++;
		i -= sizeof(struct acpi_mcfg_allocation);
	}
	if (entries == 0) {
		pr_err(PREFIX "MMCONFIG has no entries\n");
		return -ENODEV;
	}

	cfg_table = (struct acpi_mcfg_allocation *) &mcfg[1];
	for (i = 0; i < entries; i++) {
		cfg = &cfg_table[i];
		if (acpi_mcfg_check_entry(mcfg, cfg)) {
			free_all_mmcfg();
			return -ENODEV;
		}

		if (pci_mmconfig_add(cfg->pci_segment, cfg->start_bus_number,
				   cfg->end_bus_number, cfg->address) == NULL) {
			pr_warn(PREFIX "no memory for MCFG entries\n");
			free_all_mmcfg();
			return -ENOMEM;
		}
	}

	return 0;
}

static void __init __pci_mmcfg_init(int early)
{
	pci_mmcfg_reject_broken(early);
	if (list_empty(&pci_mmcfg_list))
		return;

	if (pcibios_last_bus < 0) {
		const struct pci_mmcfg_region *cfg;

		list_for_each_entry(cfg, &pci_mmcfg_list, list) {
			if (cfg->segment)
				break;
			pcibios_last_bus = cfg->end_bus;
		}
	}

	/* Install raw_pci_ops */
	if (pci_mmcfg_arch_init())
		pci_probe = (pci_probe & ~PCI_PROBE_MASK) | PCI_PROBE_MMCONF;
	else {
		free_all_mmcfg();
		pci_mmcfg_arch_init_failed = true;
	}
}

static int __initdata known_bridge;

/*
 * Lego only has one version of mmcfg init.
 * It is invoked at early PCI subsystem init phase
 * to install the extended pci ops.
 */
void __init pci_mmcfg_early_init(void)
{
	if (pci_probe & PCI_PROBE_MMCONF) {
		/*
		 * First check if it is a known bridge, by walking
		 * through predefined callbacks. If none of them is
		 * found, we consult ACPI MCFG table to get the info.
		 *
		 * In our DELL PowerEdge machines, we end up using ACPI.
		 * I guess mostly current machines will like this.
		 *
		 * 	- ys
		 */
		if (pci_mmcfg_check_hostbridge())
			known_bridge = 1;
		else
			acpi_parse_table(ACPI_SIG_MCFG, pci_parse_mcfg);
		__pci_mmcfg_init(1);
	}
}
